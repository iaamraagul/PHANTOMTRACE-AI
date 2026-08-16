import { Canvas, useFrame } from '@react-three/fiber';
import { useMemo, useRef } from 'react';
import * as THREE from 'three';

type Props = {
  risk: number;
  reducedMotion: boolean;
  points: number[];
};

function Signal({ risk, reducedMotion, points }: Props) {
  const group = useRef<THREE.Group>(null);
  const core = useRef<THREE.Mesh>(null);
  const cloud = useRef<THREE.Points>(null);
  const color = risk >= 70 ? '#d95c4a' : risk >= 40 ? '#e9a23b' : '#8fa36a';
  const accent = risk >= 70 ? '#ff6b5f' : risk >= 40 ? '#f3b44e' : '#66e4df';
  const nodes = useMemo(() => {
    const values = points.length ? points : [risk, 22, 48, 71, 34];
    return values.concat(values).slice(0, 64).map((value, index) => {
      const angle = index * 1.618;
      const radius = 1.05 + (value / 100) * 1.45 + Math.sin(index) * 0.12;
      return {
        position: [Math.cos(angle) * radius, ((index % 7) - 3) * 0.18, Math.sin(angle) * radius] as [number, number, number],
        scale: 0.035 + value / 1700,
        color: value >= 70 ? '#d95c4a' : value >= 40 ? '#e9a23b' : '#8fa36a',
      };
    });
  }, [points, risk]);

  const particles = useMemo(() => {
    const count = 1200;
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const cyan = new THREE.Color('#60d3e4');
    const blue = new THREE.Color('#4f8cff');
    const warning = new THREE.Color(accent);
    for (let index = 0; index < count; index += 1) {
      const theta = Math.acos(2 * Math.random() - 1);
      const phi = Math.random() * Math.PI * 2;
      const radius = 1.35 + Math.random() * 1.55 + (risk / 100) * 0.35;
      positions[index * 3] = radius * Math.sin(theta) * Math.cos(phi);
      positions[index * 3 + 1] = radius * Math.cos(theta) * 0.82;
      positions[index * 3 + 2] = radius * Math.sin(theta) * Math.sin(phi);
      const mixed = index % 8 === 0 ? warning : cyan.clone().lerp(blue, Math.random() * 0.75);
      colors[index * 3] = mixed.r;
      colors[index * 3 + 1] = mixed.g;
      colors[index * 3 + 2] = mixed.b;
    }
    return { positions, colors };
  }, [accent, risk]);

  useFrame((state, delta) => {
    if (!group.current || reducedMotion) return;
    const time = state.clock.elapsedTime;
    const intensity = risk >= 70 ? 1.7 : risk >= 40 ? 1.25 : 0.82;
    group.current.rotation.y += delta * 0.12 * intensity;
    group.current.rotation.z = Math.sin(time * 0.22) * 0.08;
    group.current.rotation.x = Math.cos(time * 0.16) * 0.06;
    if (core.current) {
      const pulse = 1 + Math.sin(time * (1.4 + risk / 80)) * 0.035 * intensity;
      core.current.scale.setScalar(pulse);
    }
    if (cloud.current) {
      cloud.current.rotation.y -= delta * 0.06 * intensity;
      cloud.current.rotation.x = Math.sin(time * 0.12) * 0.12;
    }
  });

  return (
    <group ref={group}>
      <points ref={cloud}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[particles.positions, 3]} />
          <bufferAttribute attach="attributes-color" args={[particles.colors, 3]} />
        </bufferGeometry>
        <pointsMaterial size={0.014} vertexColors transparent opacity={0.72} depthWrite={false} blending={THREE.AdditiveBlending} />
      </points>
      <mesh ref={core}>
        <icosahedronGeometry args={[1.08 + risk / 260, 3]} />
        <meshStandardMaterial color={color} wireframe transparent opacity={0.72} emissive={color} emissiveIntensity={0.18} />
      </mesh>
      <mesh scale={0.72}>
        <icosahedronGeometry args={[1.02, 1]} />
        <meshStandardMaterial color="#071728" transparent opacity={0.54} roughness={0.38} metalness={0.35} />
      </mesh>
      <mesh rotation={[0.7, 0.2, 0]}>
        <torusGeometry args={[2.13, 0.008, 16, 180]} />
        <meshBasicMaterial color={accent} transparent opacity={0.72} />
      </mesh>
      <mesh rotation={[1.7, 0.8, 0.2]}>
        <torusGeometry args={[1.72, 0.007, 16, 180]} />
        <meshBasicMaterial color="#d8fbff" transparent opacity={0.46} />
      </mesh>
      <mesh rotation={[1.1, -0.9, 0.8]}>
        <torusGeometry args={[2.48, 0.005, 12, 220]} />
        <meshBasicMaterial color="#60d3e4" transparent opacity={0.28} />
      </mesh>
      {nodes.map((node, index) => (
        <mesh key={index} position={node.position} scale={node.scale}>
          <sphereGeometry args={[1, 10, 10]} />
          <meshBasicMaterial color={node.color} />
        </mesh>
      ))}
    </group>
  );
}

export default function ThreatScene(props: Props) {
  return (
    <Canvas camera={{ position: [0, 0, 5.2], fov: 42 }} dpr={[1, 1.7]} aria-hidden="true">
      <color attach="background" args={['#06111d']} />
      <fog attach="fog" args={['#06111d', 4.2, 8.2]} />
      <ambientLight intensity={0.72} />
      <pointLight position={[3, 2, 4]} intensity={1.8} color="#60d3e4" />
      <pointLight position={[-3, -2, 3]} intensity={0.9} color="#4f8cff" />
      <Signal {...props} />
    </Canvas>
  );
}
