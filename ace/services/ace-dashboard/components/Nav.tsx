import Link from 'next/link';

const links = [
  { href: '/', label: 'Overview' },
  { href: '/alerts', label: 'Alerts' },
  { href: '/assets', label: 'Assets' },
  { href: '/mitre', label: 'MITRE' },
  { href: '/threat-intel', label: 'Threat Intel' },
];

export default function Nav() {
  return (
    <nav className="border-b border-ace-border bg-ace-card">
      <div className="max-w-7xl mx-auto px-4 flex items-center gap-8 h-14">
        <span className="font-bold text-red-500 text-lg tracking-wider">ACE</span>
        {links.map(l => (
          <Link
            key={l.href}
            href={l.href}
            className="text-sm text-slate-400 hover:text-white transition-colors"
          >
            {l.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
