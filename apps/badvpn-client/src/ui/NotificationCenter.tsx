import { AlertTriangle, Bell, CheckCircle2, X } from "lucide-react";

export type NotificationTone = "info" | "success" | "warning" | "error";

export type AppNotification = {
  id: string;
  tone: NotificationTone;
  title: string;
  message: string;
  actionLabel?: string;
  action?: () => void;
  createdAt: number;
  autoDismiss: boolean;
};

export function NotificationCenter({
  notifications,
  dismiss,
}: {
  notifications: AppNotification[];
  dismiss: (id: string) => void;
}) {
  if (!notifications.length) {
    return null;
  }

  return (
    <aside className="notificationViewport" aria-label="Notifications">
      {notifications.map((notification) => (
        <div
          key={notification.id}
          className={`notificationToast ${notification.tone}`}
          role={notification.tone === "error" || notification.tone === "warning" ? "alert" : "status"}
        >
          <div className="notificationIcon" aria-hidden="true">
            {notification.tone === "success" ? <CheckCircle2 size={18} /> : null}
            {notification.tone === "warning" ? <AlertTriangle size={18} /> : null}
            {notification.tone === "error" ? <AlertTriangle size={18} /> : null}
            {notification.tone === "info" ? <Bell size={18} /> : null}
          </div>
          <div className="notificationBody">
            <strong>{notification.title}</strong>
            <span>{notification.message}</span>
            {notification.action && notification.actionLabel ? (
              <button className="notificationAction" type="button" onClick={notification.action}>
                {notification.actionLabel}
              </button>
            ) : null}
          </div>
          <button className="notificationClose" type="button" onClick={() => dismiss(notification.id)} aria-label="Dismiss notification">
            <X size={15} aria-hidden="true" />
          </button>
        </div>
      ))}
    </aside>
  );
}
