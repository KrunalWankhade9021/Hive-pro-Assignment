import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono, IBM_Plex_Serif } from "next/font/google";
import "./globals.css";

// One family, three cuts. Plex was drawn for technical documentation, which is
// what this is; the mono is its native companion, so CVE and control ids sit in
// the same voice as the prose around them rather than a borrowed one. The serif
// is reserved for the MDR advisory, the one human-written document on the page.
const plexSans = IBM_Plex_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-sans",
  display: "swap",
});

const plexMono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-mono",
  display: "swap",
});

const plexSerif = IBM_Plex_Serif({
  subsets: ["latin"],
  weight: ["400", "500"],
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap",
});

export const metadata: Metadata = {
  title: "TawasolPay Cyber Risk Briefing",
  description: "Prioritised, explainable cyber risk briefing with retrieved NIST SP 800-53 guidance.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${plexSans.variable} ${plexMono.variable} ${plexSerif.variable} antialiased`}>
        {children}
      </body>
    </html>
  );
}
