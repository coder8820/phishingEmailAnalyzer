'use client'

import React, { useEffect, useRef, useState } from 'react'
import * as THREE from 'three'

interface Cyber3DBackgroundProps {
  className?: string
  intensity?: number
}

export function Cyber3DBackground({ className = '', intensity = 1 }: Cyber3DBackgroundProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [hasWebGL, setHasWebGL] = useState(true)

  useEffect(() => {
    // Check WebGL availability
    try {
      const canvas = document.createElement('canvas')
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
      if (!gl) {
        setHasWebGL(false)
        return
      }
    } catch {
      setHasWebGL(false)
      return
    }

    const container = containerRef.current
    if (!container) return

    // Check reduced motion preference
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches

    // --- Scene Setup ---
    const scene = new THREE.Scene()
    scene.fog = new THREE.FogExp2(0x060b17, 0.0018)

    const camera = new THREE.PerspectiveCamera(
      55,
      window.innerWidth / window.innerHeight,
      1,
      1000
    )
    camera.position.z = 240

    const renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: true,
      powerPreference: 'high-performance',
    })
    renderer.setSize(window.innerWidth, window.innerHeight)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setClearColor(0x000000, 0)
    container.appendChild(renderer.domElement)

    // --- Lighting ---
    const ambientLight = new THREE.AmbientLight(0x0a2540, 1.2 * intensity)
    scene.add(ambientLight)

    const pointLightCyan = new THREE.PointLight(0x06b6d4, 2 * intensity, 400)
    pointLightCyan.position.set(-100, 80, 100)
    scene.add(pointLightCyan)

    const pointLightBlue = new THREE.PointLight(0x3b82f6, 1.8 * intensity, 400)
    pointLightBlue.position.set(100, -80, 80)
    scene.add(pointLightBlue)

    // --- Cyber Plexus: Connected Particles & Network ---
    const particleCount = 140
    const particlePositions = new Float32Array(particleCount * 3)
    const particleVelocities: THREE.Vector3[] = []
    const range = 260

    for (let i = 0; i < particleCount; i++) {
      const x = (Math.random() - 0.5) * range * 1.6
      const y = (Math.random() - 0.5) * range
      const z = (Math.random() - 0.5) * range * 0.8
      particlePositions[i * 3] = x
      particlePositions[i * 3 + 1] = y
      particlePositions[i * 3 + 2] = z

      particleVelocities.push(
        new THREE.Vector3(
          (Math.random() - 0.5) * 0.15,
          (Math.random() - 0.5) * 0.15,
          (Math.random() - 0.5) * 0.1
        )
      )
    }

    const particlesGeometry = new THREE.BufferGeometry()
    particlesGeometry.setAttribute('position', new THREE.BufferAttribute(particlePositions, 3))

    // Particle sprite using canvas texture
    const canvas = document.createElement('canvas')
    canvas.width = 32
    canvas.height = 32
    const ctx = canvas.getContext('2d')
    if (ctx) {
      const grad = ctx.createRadialGradient(16, 16, 0, 16, 16, 16)
      grad.addColorStop(0, 'rgba(6, 182, 212, 1)')
      grad.addColorStop(0.3, 'rgba(59, 130, 246, 0.8)')
      grad.addColorStop(0.7, 'rgba(59, 130, 246, 0.2)')
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)')
      ctx.fillStyle = grad
      ctx.beginPath()
      ctx.arc(16, 16, 16, 0, Math.PI * 2)
      ctx.fill()
    }
    const particleTexture = new THREE.CanvasTexture(canvas)

    const particlesMaterial = new THREE.PointsMaterial({
      color: 0x38bdf8,
      size: 4.5,
      map: particleTexture,
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      opacity: 0.85,
    })

    const particleSystem = new THREE.Points(particlesGeometry, particlesMaterial)
    scene.add(particleSystem)

    // Lines connecting nearby nodes
    const maxLines = (particleCount * (particleCount - 1)) / 2
    const linePositions = new Float32Array(maxLines * 6)
    const lineColors = new Float32Array(maxLines * 6)

    const linesGeometry = new THREE.BufferGeometry()
    linesGeometry.setAttribute('position', new THREE.BufferAttribute(linePositions, 3))
    linesGeometry.setAttribute('color', new THREE.BufferAttribute(lineColors, 3))

    const linesMaterial = new THREE.LineBasicMaterial({
      vertexColors: true,
      transparent: true,
      blending: THREE.AdditiveBlending,
      opacity: 0.35,
      depthWrite: false,
    })

    const lineMesh = new THREE.LineSegments(linesGeometry, linesMaterial)
    scene.add(lineMesh)

    // --- Floating Wireframe Security Core (Shield / Polyhedron) ---
    const coreGroup = new THREE.Group()

    // Outer wireframe icosahedron
    const outerGeo = new THREE.IcosahedronGeometry(48, 1)
    const outerMat = new THREE.MeshBasicMaterial({
      color: 0x06b6d4,
      wireframe: true,
      transparent: true,
      opacity: 0.18,
    })
    const outerMesh = new THREE.Mesh(outerGeo, outerMat)
    coreGroup.add(outerMesh)

    // Inner glowing wireframe dodecahedron
    const innerGeo = new THREE.DodecahedronGeometry(30, 0)
    const innerMat = new THREE.MeshBasicMaterial({
      color: 0x3b82f6,
      wireframe: true,
      transparent: true,
      opacity: 0.3,
    })
    const innerMesh = new THREE.Mesh(innerGeo, innerMat)
    coreGroup.add(innerMesh)

    // Central core point light & glowing sphere
    const coreSphereGeo = new THREE.SphereGeometry(6, 16, 16)
    const coreSphereMat = new THREE.MeshBasicMaterial({
      color: 0x38bdf8,
      transparent: true,
      opacity: 0.6,
    })
    const coreSphere = new THREE.Mesh(coreSphereGeo, coreSphereMat)
    coreGroup.add(coreSphere)

    coreGroup.position.set(0, 0, -30)
    scene.add(coreGroup)

    // --- Parallax & Mouse Interactivity ---
    let mouseX = 0
    let mouseY = 0
    let targetCameraX = 0
    let targetCameraY = 0

    const handleMouseMove = (e: MouseEvent) => {
      mouseX = (e.clientX / window.innerWidth) * 2 - 1
      mouseY = -(e.clientY / window.innerHeight) * 2 + 1
      targetCameraX = mouseX * 24
      targetCameraY = mouseY * 16
    }

    window.addEventListener('mousemove', handleMouseMove, { passive: true })

    // --- Resize Handler ---
    const handleResize = () => {
      camera.aspect = window.innerWidth / window.innerHeight
      camera.updateProjectionMatrix()
      renderer.setSize(window.innerWidth, window.innerHeight)
    }

    window.addEventListener('resize', handleResize)

    // --- Animation Loop ---
    let animationFrameId: number
    let clock = new THREE.Clock()

    const animate = () => {
      animationFrameId = requestAnimationFrame(animate)

      const delta = clock.getDelta()
      const time = clock.getElapsedTime()

      // Smooth camera parallax
      if (!prefersReducedMotion) {
        camera.position.x += (targetCameraX - camera.position.x) * 0.035
        camera.position.y += (targetCameraY - camera.position.y) * 0.035
      }
      camera.lookAt(0, 0, 0)

      // Rotate security core
      if (!prefersReducedMotion) {
        coreGroup.rotation.y += 0.003
        coreGroup.rotation.x += 0.0015
        innerMesh.rotation.y -= 0.005
        innerMesh.rotation.z += 0.002
      }

      // Gentle core float
      coreGroup.position.y = Math.sin(time * 0.8) * 6

      // Update particles and lines
      const positions = particlesGeometry.attributes.position.array as Float32Array
      let lineVertexIndex = 0
      let lineColorsIndex = 0
      const connectDistance = 55
      const connectDistSq = connectDistance * connectDistance

      for (let i = 0; i < particleCount; i++) {
        const i3 = i * 3
        if (!prefersReducedMotion) {
          positions[i3] += particleVelocities[i].x
          positions[i3 + 1] += particleVelocities[i].y
          positions[i3 + 2] += particleVelocities[i].z

          // Boundary bounce
          const boundX = range * 0.8
          const boundY = range * 0.5
          const boundZ = range * 0.4
          if (Math.abs(positions[i3]) > boundX) particleVelocities[i].x *= -1
          if (Math.abs(positions[i3 + 1]) > boundY) particleVelocities[i].y *= -1
          if (Math.abs(positions[i3 + 2]) > boundZ) particleVelocities[i].z *= -1
        }

        // Connect nearby nodes with glowing cyber plexus threads
        for (let j = i + 1; j < particleCount; j++) {
          const j3 = j * 3
          const dx = positions[i3] - positions[j3]
          const dy = positions[i3 + 1] - positions[j3 + 1]
          const dz = positions[i3 + 2] - positions[j3 + 2]
          const distSq = dx * dx + dy * dy + dz * dz

          if (distSq < connectDistSq) {
            const alpha = 1.0 - Math.sqrt(distSq) / connectDistance

            linePositions[lineVertexIndex++] = positions[i3]
            linePositions[lineVertexIndex++] = positions[i3 + 1]
            linePositions[lineVertexIndex++] = positions[i3 + 2]

            linePositions[lineVertexIndex++] = positions[j3]
            linePositions[lineVertexIndex++] = positions[j3 + 1]
            linePositions[lineVertexIndex++] = positions[j3 + 2]

            const colorR = 0.02 * alpha
            const colorG = 0.71 * alpha
            const colorB = 0.83 * alpha

            lineColors[lineColorsIndex++] = colorR
            lineColors[lineColorsIndex++] = colorG
            lineColors[lineColorsIndex++] = colorB

            lineColors[lineColorsIndex++] = colorR
            lineColors[lineColorsIndex++] = colorG
            lineColors[lineColorsIndex++] = colorB
          }
        }
      }

      particlesGeometry.attributes.position.needsUpdate = true
      linesGeometry.attributes.position.needsUpdate = true
      linesGeometry.attributes.color.needsUpdate = true
      linesGeometry.setDrawRange(0, lineVertexIndex / 3)

      renderer.render(scene, camera)
    }

    animate()

    // --- Cleanup on Unmount ---
    return () => {
      cancelAnimationFrame(animationFrameId)
      window.removeEventListener('mousemove', handleMouseMove)
      window.removeEventListener('resize', handleResize)

      // Dispose Three.js objects
      particlesGeometry.dispose()
      particlesMaterial.dispose()
      particleTexture.dispose()

      linesGeometry.dispose()
      linesMaterial.dispose()

      outerGeo.dispose()
      outerMat.dispose()
      innerGeo.dispose()
      innerMat.dispose()
      coreSphereGeo.dispose()
      coreSphereMat.dispose()

      renderer.dispose()

      if (container && renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
    }
  }, [intensity])

  return (
    <div
      ref={containerRef}
      aria-hidden="true"
      className={`fixed inset-0 pointer-events-none z-0 overflow-hidden ${className}`}
    >
      {/* Fallback CSS cyber gradient if WebGL is unavailable */}
      {!hasWebGL && (
        <div className="absolute inset-0 bg-gradient-to-br from-navy-950 via-navy-900 to-[#071329] opacity-90" />
      )}
    </div>
  )
}
