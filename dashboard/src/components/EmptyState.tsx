import { LucideIcon, Package } from "lucide-react";

export default function EmptyState({
  message,
  title,
  description,
  icon,
  action,
}: {
  message?: string;
  title?: string;
  description?: string;
  icon?: LucideIcon;
  action?: React.ReactNode;
}) {
  const Icon = icon || Package;
  return (
    <div className="flex flex-col items-center justify-center py-16 text-slate-500">
      <Icon className="w-16 h-16 mb-4 opacity-30" />
      {title && <p className="text-lg font-medium text-slate-300 mb-1">{title}</p>}
      {description && <p className="text-sm text-slate-500 mb-2">{description}</p>}
      {message && <p className="text-lg mb-2">{message}</p>}
      {action}
    </div>
  );
}
