import './globals.css'
import Navbar from '../components/Navbar'

export const metadata = {
  title: 'IoT Security Analyzer',
  description: 'Cybersecurity threat analysis for IoT devices and networks',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="font-sans">{' '}
        <Navbar />
        <main className="min-h-screen pt-16">
          {children}
        </main>
      </body>
    </html>
  )
}
