export function Logo({ size = 20 }: { size?: number }) {
  return (
    <svg viewBox="0 0 64 64" width={size} height={size} fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M32 13 L39.5 19.5 L38 3 L49 5.5 L55 33 L42.5 40 L32 60 L21.5 40 L9 33 L15 5.5 L26 3 L24.5 19.5 Z M17.5 30.5 L25 26.5 L27 31 L19.5 35 Z M46.5 30.5 L39 26.5 L37 31 L44.5 35 Z" />
    </svg>
  )
}
