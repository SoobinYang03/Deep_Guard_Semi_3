import { useCallback } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Controls,
  Background,
  BackgroundVariant,
  MiniMap,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

interface NetworkDiagramProps {
  targetIp: string;
  openPorts: number[];
}

export function NetworkDiagram({ targetIp, openPorts }: NetworkDiagramProps) {
  // 노드 생성
  const initialNodes: Node[] = [
    {
      id: 'scanner',
      type: 'input',
      data: { label: '스캐너' },
      position: { x: 250, y: 0 },
      style: { background: '#3b82f6', color: 'white', padding: '10px 20px', borderRadius: '8px' },
    },
    {
      id: 'target',
      data: { label: `타겟\n${targetIp}` },
      position: { x: 250, y: 150 },
      style: { background: '#10b981', color: 'white', padding: '10px 20px', borderRadius: '8px', whiteSpace: 'pre' },
    },
    ...openPorts.slice(0, 8).map((port, index) => {
      const angle = (index / 8) * 2 * Math.PI;
      const radius = 200;
      const x = 250 + radius * Math.cos(angle);
      const y = 350 + radius * Math.sin(angle);
      
      return {
        id: `port-${port}`,
        type: 'output',
        data: { label: `포트 ${port}` },
        position: { x, y },
        style: { background: '#ef4444', color: 'white', padding: '8px 16px', borderRadius: '6px', fontSize: '12px' },
      };
    }),
  ];

  // 엣지 생성
  const initialEdges: Edge[] = [
    {
      id: 'scanner-target',
      source: 'scanner',
      target: 'target',
      animated: true,
      style: { stroke: '#3b82f6', strokeWidth: 2 },
    },
    ...openPorts.slice(0, 8).map((port) => ({
      id: `target-port-${port}`,
      source: 'target',
      target: `port-${port}`,
      animated: true,
      style: { stroke: '#10b981' },
    })),
  ];

  const [nodes, _, onNodesChange] = useNodesState(initialNodes);
  const [edges, __, onEdgesChange] = useEdgesState(initialEdges);

  return (
    <Card>
      <CardHeader>
        <CardTitle>네트워크 다이어그램</CardTitle>
      </CardHeader>
      <CardContent>
        <div style={{ height: '500px', border: '1px solid #e5e7eb', borderRadius: '8px' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
          >
            <Background variant={BackgroundVariant.Dots} gap={12} size={1} />
            <Controls />
            <MiniMap />
          </ReactFlow>
        </div>
      </CardContent>
    </Card>
  );
}
