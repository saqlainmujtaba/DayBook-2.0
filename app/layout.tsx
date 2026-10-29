import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Daybook — Prayer & Quran",
  description: "A gentle place to keep track of your prayers and time with the Quran.",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><head><link rel="preconnect" href="https://fonts.googleapis.com"/><link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous"/><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Playfair+Display:wght@500;600;700&display=swap" rel="stylesheet"/></head><body>{children}</body></html>;
}
