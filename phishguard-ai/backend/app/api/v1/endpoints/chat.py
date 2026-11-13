"""
PhishGuard AI — Chat Assistant API Endpoints
Handles chat sessions, message streaming/generation, history management,
clearing/deleting chats, and external resource catalog.
"""
from __future__ import annotations

import uuid
from typing import Any, List, Optional
from datetime import datetime, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import ChatSession, ChatMessage, User
from app.security.auth import get_current_user
from app.services.chat_assistant_service import (
    ChatAssistantService,
    CYBER_RESOURCES,
    generate_session_title,
)
from app.utils.response import success_response, error_response

logger = structlog.get_logger(__name__)
router = APIRouter()


# ============================================================
# SCHEMAS
# ============================================================
class SendMessageRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000, description="User prompt or query")


class CreateSessionRequest(BaseModel):
    title: Optional[str] = Field(None, max_length=255, description="Initial conversation title")


# ============================================================
# ENDPOINTS
# ============================================================
@router.get("/resources", summary="Get catalog of verified external cybersecurity resources")
async def get_cyber_resources():
    """Return verified external cybersecurity tools, threat intelligence feeds, and sandboxes."""
    return success_response(data=CYBER_RESOURCES)


@router.get("/sessions", summary="List chat sessions for the authenticated analyst")
async def list_chat_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve all chat sessions for the current user, ordered by most recently updated."""
    query = (
        select(
            ChatSession.id,
            ChatSession.title,
            ChatSession.created_at,
            ChatSession.updated_at,
            func.count(ChatMessage.id).label("message_count"),
        )
        .outerjoin(ChatMessage, ChatMessage.session_id == ChatSession.id)
        .where(
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
        .group_by(ChatSession.id)
        .order_by(desc(ChatSession.updated_at))
    )
    result = await db.execute(query)
    rows = result.all()

    sessions = [
        {
            "id": str(row.id),
            "title": row.title,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "message_count": row.message_count,
        }
        for row in rows
    ]

    return success_response(data=sessions)


@router.post("/sessions", summary="Create a new chat conversation session")
async def create_chat_session(
    payload: Optional[CreateSessionRequest] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new empty conversation session."""
    title = (payload.title if payload and payload.title else "New Conversation").strip()
    session = ChatSession(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        title=title,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    return success_response(
        data={
            "id": str(session.id),
            "title": session.title,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
            "messages": [],
        },
        status_code=status.HTTP_201_CREATED,
    )


@router.get("/sessions/{session_id}", summary="Get chat session details and message history")
async def get_chat_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch session info and full ordered message history."""
    query = (
        select(ChatSession)
        .options(selectinload(ChatSession.messages))
        .where(
            ChatSession.id == session_id,
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        return error_response(
            code="SESSION_NOT_FOUND",
            message="Conversation session not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    messages = [
        {
            "id": str(m.id),
            "sender": m.sender,
            "content": m.content,
            "sources": m.sources or [],
            "created_at": m.created_at.isoformat() if m.created_at else None,
        }
        for m in session.messages
    ]

    return success_response(
        data={
            "id": str(session.id),
            "title": session.title,
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "updated_at": session.updated_at.isoformat() if session.updated_at else None,
            "messages": messages,
        }
    )


@router.post("/sessions/{session_id}/messages", summary="Send a user message and receive AI assistant response")
async def send_chat_message(
    session_id: uuid.UUID,
    payload: SendMessageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit a query to the AI assistant, update history, and receive structured response with sources."""
    query = (
        select(ChatSession)
        .options(selectinload(ChatSession.messages))
        .where(
            ChatSession.id == session_id,
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        return error_response(
            code="SESSION_NOT_FOUND",
            message="Conversation session not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    user_text = payload.content.strip()
    if not user_text:
        return error_response(
            code="EMPTY_CONTENT",
            message="Message content cannot be empty.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # 1. Save User Message
    user_msg = ChatMessage(
        session_id=session.id,
        sender="user",
        content=user_text,
        sources=[],
    )
    db.add(user_msg)
    await db.flush()

    # 2. Prepare conversation history for context
    history = [
        {"sender": m.sender, "content": m.content}
        for m in session.messages
    ]

    # 3. Call AI Assistant Service
    assistant_content, sources = await ChatAssistantService.answer_query(
        user_message=user_text,
        conversation_history=history,
    )

    # 4. Save Assistant Message
    assistant_msg = ChatMessage(
        session_id=session.id,
        sender="assistant",
        content=assistant_content,
        sources=sources,
    )
    db.add(assistant_msg)

    # 5. Smart Title Update if needed
    if session.title in ["New Conversation", "", None] or len(session.messages) <= 1:
        session.title = generate_session_title(user_text)

    session.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return success_response(
        data={
            "session_id": str(session.id),
            "session_title": session.title,
            "user_message": {
                "id": str(user_msg.id),
                "sender": user_msg.sender,
                "content": user_msg.content,
                "sources": [],
                "created_at": user_msg.created_at.isoformat() if user_msg.created_at else None,
            },
            "assistant_message": {
                "id": str(assistant_msg.id),
                "sender": assistant_msg.sender,
                "content": assistant_msg.content,
                "sources": assistant_msg.sources or [],
                "created_at": assistant_msg.created_at.isoformat() if assistant_msg.created_at else None,
            },
        }
    )


@router.delete("/sessions/{session_id}/clear", summary="Clear all messages in a chat session")
async def clear_chat_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Clear message history in the specified session without removing the session itself."""
    query = (
        select(ChatSession)
        .where(
            ChatSession.id == session_id,
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        return error_response(
            code="SESSION_NOT_FOUND",
            message="Conversation session not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Delete all messages belonging to this session
    await db.execute(delete(ChatMessage).where(ChatMessage.session_id == session.id))
    session.title = "New Conversation"
    session.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return success_response(
        data={"session_id": str(session.id), "cleared": True},
        message="Chat history cleared successfully.",
    )


@router.delete("/sessions/{session_id}", summary="Delete an entire chat session")
async def delete_chat_session(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a conversation session and all its messages."""
    query = (
        select(ChatSession)
        .where(
            ChatSession.id == session_id,
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
    )
    result = await db.execute(query)
    session = result.scalar_one_or_none()

    if not session:
        return error_response(
            code="SESSION_NOT_FOUND",
            message="Conversation session not found.",
            status_code=status.HTTP_404_NOT_FOUND,
        )

    await db.delete(session)
    await db.commit()

    return success_response(
        data={"session_id": str(session_id), "deleted": True},
        message="Conversation deleted successfully.",
    )


@router.delete("/sessions", summary="Delete all chat history for current user")
async def delete_all_chat_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete all conversation sessions for the current user."""
    del_query = (
        delete(ChatSession)
        .where(
            ChatSession.organization_id == current_user.organization_id,
            ChatSession.user_id == current_user.id,
        )
    )
    await db.execute(del_query)
    await db.commit()

    return success_response(
        data={"deleted_all": True},
        message="All chat history deleted successfully.",
    )
