import "./globals.css";

export const metadata = {
  title: "SentinelAI — Code Reviewer",
  description: "Phase 1 AI Code Reviewer and Security Scanner"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="en"><body>{children}</body></html>;
}
