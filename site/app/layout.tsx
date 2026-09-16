import type { Metadata } from "next";
import { Archivo, Spline_Sans_Mono } from "next/font/google";
import "./globals.css";
import { Descent } from "@/components/Descent";

/**
 * Two faces, chosen as objects from the survey world rather than by category
 * association.
 *
 * Archivo is a grotesque drawn for high-performance print: charts, signage, forms
 * set small and read fast under bad light. It carries the log's headings and its
 * prose without the engineered-serif costume a "technical" page usually reaches
 * for.
 *
 * Spline Sans Mono sets every measured value, and only measured values. Its
 * figures are tabular and its skeleton is the same grotesque as Archivo, so a
 * reading dropped into a sentence sits on the same baseline logic as the words
 * around it.
 *
 * Both are self-hosted and subset by next/font: no render-blocking third-party
 * CSS, no layout shift as they swap.
 */
const archivo = Archivo({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-archivo",
  display: "swap",
});

const splineMono = Spline_Sans_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "700"],
  variable: "--font-spline-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "QI-Fingerprint — a cored section through an ECDSA signature corpus",
  description:
    "Which nonce-generation bug is leaking private keys, and which other keys share it. Four stages over unlabeled ECDSA signatures, every recovery gated on d·G == Q. Classification measured on synthetic corpora; recovery validated against a real reused-nonce key from block 252,474.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${archivo.variable} ${splineMono.variable}`}>
      <body className="grain relative">
        <a className="skip-link" href="#log">
          Skip to the log
        </a>
        <Descent />
        {children}
      </body>
    </html>
  );
}
