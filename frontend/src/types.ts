export type Me = { id: string; name: string; org_admin: boolean; playground: boolean; agentyzer: { enabled: boolean; mode: string }; vscorer_url: string; workspaces: { id: string; name: string; capabilities: string[] }[] }
export type Project = { id: string; name: string; workspace_id: string; capabilities: string[]; workspace?: string }
export type Job = { id: string; kind: string; status: string; error: string; result: Record<string, unknown>; attempts: number; project_id?: string; version?: string }
