/** Join class names, skipping falsy values. Lets long Tailwind strings span several lines. */
export function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}
