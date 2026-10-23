/**
 * Date and time formatting utility in Indian Standard Time (IST) / Asia/Kolkata.
 * Used for authoritative server timestamps across Admin monitoring pages and feeds.
 */

export function formatISTDate(isoString: string): string {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    // Format: "23 Oct 2026"
    return new Intl.DateTimeFormat('en-IN', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      timeZone: 'Asia/Kolkata',
    }).format(d);
  } catch {
    return isoString;
  }
}

export function formatISTTime(isoString: string): string {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    // Format: "02:15:32 PM IST"
    const timeStr = new Intl.DateTimeFormat('en-IN', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
      timeZone: 'Asia/Kolkata',
    }).format(d);
    return `${timeStr.toUpperCase()} IST`;
  } catch {
    return isoString;
  }
}

export function formatISTDateTime(isoString: string): string {
  if (!isoString) return '—';
  return `${formatISTDate(isoString)}, ${formatISTTime(isoString)}`;
}

export function getActionDisplayLabel(action: string): string {
  switch (action) {
    case 'LOGIN_SUCCESS':
    case 'login':
      return 'Signed In';
    case 'LOGOUT_SUCCESS':
    case 'logout':
      return 'Signed Out';
    case 'LOGIN_FAILED':
    case 'login_failure':
      return 'Login Failed';
    case 'register':
      return 'Signed Up';
    case 'register_failure':
      return 'Registration Failed';
    case 'upload':
    case 'version_upload':
      return 'Document Uploaded';
    case 'download':
      return 'Document Downloaded';
    case 'preview':
      return 'Document Previewed';
    case 'permission_grant':
      return 'Permission Granted';
    case 'permission_revoke':
      return 'Permission Revoked';
    case 'permission_update':
      return 'Permission Updated';
    case 'user_created':
      return 'User Provisioned';
    case 'role_change':
      return 'Role Modified';
    case 'account_activated':
      return 'Account Activated';
    case 'account_deactivated':
      return 'Account Deactivated';
    case 'profile_update':
      return 'Profile Updated';
    case 'security_alert':
      return 'Security Alert';
    default:
      return action.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }
}

export function getStatusDisplayLabel(result: string, action?: string): { label: 'Success' | 'Failed'; isSuccess: boolean } {
  if (action === 'LOGIN_FAILED' || action === 'login_failure' || action === 'register_failure' || result === 'denied') {
    return { label: 'Failed', isSuccess: false };
  }
  return { label: 'Success', isSuccess: true };
}
