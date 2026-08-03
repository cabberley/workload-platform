import type { CSSProperties } from "react";

/** Shared inline style tokens so the small components stay consistent without a CSS toolchain. */
export const th: CSSProperties = {
  textAlign: "left",
  borderBottom: "2px solid #ddd",
  padding: 8,
  fontSize: 13,
};

export const td: CSSProperties = { borderBottom: "1px solid #eee", padding: 8, fontSize: 13 };

export const card: CSSProperties = {
  border: "1px solid #e0e0e0",
  borderRadius: 8,
  padding: 16,
  background: "#fff",
};

export const muted: CSSProperties = { color: "#5f6368", fontSize: 13 };
