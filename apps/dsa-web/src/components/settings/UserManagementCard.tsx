import type React from 'react';
import { useCallback, useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { KeyRound, Plus, RefreshCw, ShieldCheck, Trash2, UserCog } from 'lucide-react';
import { useAuth } from '../../hooks';
import { useUiLanguage } from '../../contexts/UiLanguageContext';
import { ApiErrorAlert, Button, ConfirmDialog, Input } from '../common';
import { usersApi, type UserRecord, type UserRole } from '../../api/users';
import { createParsedApiError, getParsedApiError, type ParsedApiError } from '../../api/error';
import { cn } from '../../utils/cn';
import { SettingsAlert } from './SettingsAlert';
import { SettingsSectionCard } from './SettingsSectionCard';

type ConfirmState =
  | { open: false }
  | { open: true; kind: 'delete'; user: UserRecord }
  | { open: true; kind: 'reset'; user: UserRecord };

const RESET_DIALOG_PORTAL_ID = 'user-management-reset-dialog-root';

function ensureResetDialogPortal(): HTMLElement | null {
  if (typeof document === 'undefined') {
    return null;
  }
  let node = document.getElementById(RESET_DIALOG_PORTAL_ID);
  if (!node) {
    node = document.createElement('div');
    node.id = RESET_DIALOG_PORTAL_ID;
    document.body.appendChild(node);
  }
  return node;
}

export const UserManagementCard: React.FC = () => {
  const { currentUser } = useAuth();
  const { t } = useUiLanguage();

  const [users, setUsers] = useState<UserRecord[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<ParsedApiError | null>(null);

  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<UserRole>('user');
  const [isCreating, setIsCreating] = useState(false);
  const [createError, setCreateError] = useState<ParsedApiError | null>(null);

  const [confirm, setConfirm] = useState<ConfirmState>({ open: false });
  const [resetNewPassword, setResetNewPassword] = useState('');
  const [isPerforming, setIsPerforming] = useState(false);
  const [actionError, setActionError] = useState<ParsedApiError | null>(null);
  const [actionSuccess, setActionSuccess] = useState('');

  const refresh = useCallback(async () => {
    setLoadError(null);
    setIsRefreshing(true);
    try {
      const list = await usersApi.listUsers();
      setUsers(list);
    } catch (err) {
      setLoadError(getParsedApiError(err));
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!actionSuccess) {
      return;
    }
    const timer = window.setTimeout(() => setActionSuccess(''), 4000);
    return () => window.clearTimeout(timer);
  }, [actionSuccess]);

  // Only render for admins (defensive; SettingsPage also gates this card).
  if (!currentUser || currentUser.role !== 'admin') {
    return null;
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    setActionSuccess('');

    const trimmedUsername = newUsername.trim();
    if (!trimmedUsername) {
      setCreateError(createParsedApiError({
        title: t('settings.userManagementFailure'),
        message: t('settings.userManagementUsernamePlaceholder'),
        rawMessage: 'username required',
        category: 'missing_params',
      }));
      return;
    }
    if (newPassword.length < 6) {
      setCreateError(createParsedApiError({
        title: t('settings.userManagementFailure'),
        message: t('settings.userManagementPasswordHint'),
        rawMessage: 'password too short',
        category: 'missing_params',
      }));
      return;
    }

    setIsCreating(true);
    try {
      await usersApi.createUser({
        username: trimmedUsername,
        password: newPassword,
        role: newRole,
      });
      setNewUsername('');
      setNewPassword('');
      setNewRole('user');
      await refresh();
      setActionSuccess(t('settings.userManagementSuccess'));
    } catch (err) {
      setCreateError(getParsedApiError(err));
    } finally {
      setIsCreating(false);
    }
  };

  const handleToggleRole = async (user: UserRecord) => {
    setActionError(null);
    setActionSuccess('');
    const nextRole: UserRole = user.role === 'admin' ? 'user' : 'admin';
    try {
      await usersApi.updateUser(user.id, { role: nextRole });
      await refresh();
      setActionSuccess(t('settings.userManagementSuccess'));
    } catch (err) {
      setActionError(getParsedApiError(err));
    }
  };

  const handleToggleActive = async (user: UserRecord) => {
    setActionError(null);
    setActionSuccess('');
    try {
      await usersApi.updateUser(user.id, { isActive: !user.isActive });
      await refresh();
      setActionSuccess(t('settings.userManagementSuccess'));
    } catch (err) {
      setActionError(getParsedApiError(err));
    }
  };

  const openDeleteConfirm = (user: UserRecord) => {
    setActionError(null);
    setConfirm({ open: true, kind: 'delete', user });
  };

  const openResetPasswordConfirm = (user: UserRecord) => {
    setActionError(null);
    setResetNewPassword('');
    setConfirm({ open: true, kind: 'reset', user });
  };

  const closeConfirm = () => {
    setConfirm({ open: false });
    setResetNewPassword('');
  };

  const performConfirmedAction = async () => {
    if (!confirm.open) return;
    const user = confirm.user;

    if (confirm.kind === 'reset' && resetNewPassword.length < 6) {
      setActionError(createParsedApiError({
        title: t('settings.userManagementFailure'),
        message: t('settings.userManagementPasswordHint'),
        rawMessage: 'password too short',
        category: 'missing_params',
      }));
      return;
    }

    setIsPerforming(true);
    setActionError(null);
    try {
      if (confirm.kind === 'delete') {
        await usersApi.deleteUser(user.id);
      } else {
        await usersApi.resetPassword(user.id, resetNewPassword);
      }
      closeConfirm();
      await refresh();
      setActionSuccess(t('settings.userManagementSuccess'));
    } catch (err) {
      setActionError(getParsedApiError(err));
    } finally {
      setIsPerforming(false);
    }
  };

  const isSelf = (user: UserRecord) =>
    Boolean(currentUser.username) && currentUser.username.toLowerCase() === user.username.toLowerCase();

  const resetPortalNode = typeof document !== 'undefined' ? ensureResetDialogPortal() : null;
  const resetDialogVisible = confirm.open && confirm.kind === 'reset';

  return (
    <SettingsSectionCard
      title={t('settings.userManagement')}
      description={t('settings.userManagementDescription')}
      actions={
        <Button
          type="button"
          variant="settings-secondary"
          size="sm"
          onClick={() => void refresh()}
          disabled={isRefreshing}
          isLoading={isRefreshing}
          loadingText={t('settings.userManagementRefreshing')}
        >
          <RefreshCw className="h-4 w-4" aria-hidden="true" />
          {t('settings.userManagementRefresh')}
        </Button>
      }
    >
      <div data-testid="user-management-card" className="space-y-4">
        <form
          onSubmit={handleCreate}
          className="space-y-3 rounded-2xl border settings-border bg-background/35 px-4 py-4"
        >
          <p className="text-sm font-semibold text-foreground">
            {t('settings.userManagementCreateTitle')}
          </p>
          <div className="grid gap-3 md:grid-cols-3">
            <Input
              id="user-mgmt-new-username"
              label={t('settings.userManagementUsername')}
              placeholder={t('settings.userManagementUsernamePlaceholder')}
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              disabled={isCreating}
              autoComplete="off"
            />
            <Input
              id="user-mgmt-new-password"
              type="password"
              allowTogglePassword
              iconType="password"
              label={t('settings.userManagementPassword')}
              hint={t('settings.userManagementPasswordHint')}
              placeholder={t('settings.userManagementPasswordPlaceholder')}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              disabled={isCreating}
              autoComplete="new-password"
            />
            <div className="space-y-1.5">
              <label
                htmlFor="user-mgmt-new-role"
                className="block text-xs font-medium text-muted-text"
              >
                {t('settings.userManagementRole')}
              </label>
              <select
                id="user-mgmt-new-role"
                value={newRole}
                onChange={(e) => setNewRole(e.target.value as UserRole)}
                disabled={isCreating}
                className="h-10 w-full rounded-lg border settings-border bg-[var(--settings-surface)] px-3 text-sm text-foreground outline-none transition focus:ring-2 focus:ring-cyan/20"
              >
                <option value="user">{t('settings.userManagementRoleUser')}</option>
                <option value="admin">{t('settings.userManagementRoleAdmin')}</option>
              </select>
            </div>
          </div>
          {createError ? <ApiErrorAlert error={createError} /> : null}
          <Button
            type="submit"
            variant="settings-primary"
            size="sm"
            disabled={isCreating}
            isLoading={isCreating}
            loadingText={t('settings.userManagementCreating')}
          >
            <Plus className="h-4 w-4" aria-hidden="true" />
            {t('settings.userManagementCreate')}
          </Button>
        </form>

        <div className="space-y-3">
          <p className="text-sm font-semibold text-foreground">
            {t('settings.userManagementListTitle')}
          </p>
          {loadError ? (
            <ApiErrorAlert
              error={loadError}
              actionLabel={t('common.retry')}
              onAction={() => void refresh()}
            />
          ) : null}
          {!loadError && users.length === 0 ? (
            <p className="rounded-lg border settings-border bg-background/30 px-4 py-3 text-sm text-muted-text">
              {t('settings.userManagementEmpty')}
            </p>
          ) : null}
          {users.length > 0 ? (
            <div className="overflow-x-auto rounded-lg border settings-border bg-[var(--settings-surface)]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b settings-border bg-background/40 text-left text-xs font-semibold text-muted-text">
                    <th className="px-3 py-2">{t('settings.userManagementColumnUsername')}</th>
                    <th className="px-3 py-2">{t('settings.userManagementColumnRole')}</th>
                    <th className="px-3 py-2">{t('settings.userManagementColumnStatus')}</th>
                    <th className="hidden px-3 py-2 md:table-cell">
                      {t('settings.userManagementColumnCreatedAt')}
                    </th>
                    <th className="px-3 py-2 text-right">
                      {t('settings.userManagementColumnActions')}
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--settings-border-soft)]">
                  {users.map((user) => {
                    const selfRow = isSelf(user);
                    return (
                      <tr key={user.id} className="bg-card/30 hover:bg-hover/30">
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-medium text-foreground">{user.username}</span>
                            {selfRow ? (
                              <span className="rounded-full border settings-border bg-background/60 px-1.5 py-0.5 text-[10px] text-muted-text">
                                {t('settings.userManagementCurrentSession')}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={cn(
                              'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium',
                              user.role === 'admin'
                                ? 'border-cyan/30 bg-cyan/10 text-cyan'
                                : 'border-border/60 bg-background/40 text-muted-text',
                            )}
                          >
                            {user.role === 'admin'
                              ? <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                              : <UserCog className="h-3 w-3" aria-hidden="true" />}
                            {user.role === 'admin'
                              ? t('settings.userManagementRoleAdmin')
                              : t('settings.userManagementRoleUser')}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={cn(
                              'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium',
                              user.isActive
                                ? 'border-success/40 bg-success/10 text-success'
                                : 'border-border/60 bg-background/40 text-muted-text',
                            )}
                          >
                            {user.isActive
                              ? t('settings.userManagementActive')
                              : t('settings.userManagementInactive')}
                          </span>
                        </td>
                        <td className="hidden px-3 py-2 text-xs text-muted-text md:table-cell">
                          {user.createdAt ?? '-'}
                        </td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap items-center justify-end gap-1.5">
                            <Button
                              type="button"
                              variant="settings-secondary"
                              size="xsm"
                              onClick={() => void handleToggleRole(user)}
                              disabled={isPerforming || (selfRow && user.role === 'admin')}
                              title={
                                user.role === 'admin'
                                  ? t('settings.userManagementDemoteAdmin')
                                  : t('settings.userManagementPromoteAdmin')
                              }
                            >
                              {user.role === 'admin'
                                ? t('settings.userManagementDemoteAdmin')
                                : t('settings.userManagementPromoteAdmin')}
                            </Button>
                            <Button
                              type="button"
                              variant="settings-secondary"
                              size="xsm"
                              onClick={() => void handleToggleActive(user)}
                              disabled={isPerforming || selfRow}
                              title={
                                user.isActive
                                  ? t('settings.userManagementDeactivate')
                                  : t('settings.userManagementActivate')
                              }
                            >
                              {user.isActive
                                ? t('settings.userManagementDeactivate')
                                : t('settings.userManagementActivate')}
                            </Button>
                            <Button
                              type="button"
                              variant="settings-secondary"
                              size="xsm"
                              onClick={() => openResetPasswordConfirm(user)}
                              disabled={isPerforming}
                              title={t('settings.userManagementResetPassword')}
                            >
                              <KeyRound className="h-3 w-3" aria-hidden="true" />
                              {t('settings.userManagementResetPassword')}
                            </Button>
                            <Button
                              type="button"
                              variant="danger-subtle"
                              size="xsm"
                              onClick={() => openDeleteConfirm(user)}
                              disabled={isPerforming || selfRow}
                              title={t('settings.userManagementDelete')}
                            >
                              <Trash2 className="h-3 w-3" aria-hidden="true" />
                              {t('settings.userManagementDelete')}
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>

        {actionError ? <ApiErrorAlert error={actionError} /> : null}
        {!actionError && actionSuccess ? (
          <SettingsAlert
            title={t('settings.userManagementSuccess')}
            message={actionSuccess}
            variant="success"
          />
        ) : null}
      </div>

      <ConfirmDialog
        isOpen={confirm.open && confirm.kind === 'delete'}
        title={t('settings.userManagementDeleteTitle')}
        message={
          confirm.open && confirm.kind === 'delete'
            ? t('settings.userManagementDeleteConfirm')
            : ''
        }
        confirmText={t('settings.userManagementSubmit')}
        cancelText={t('settings.userManagementCancel')}
        isDanger
        confirmDisabled={isPerforming}
        cancelDisabled={isPerforming}
        onConfirm={() => void performConfirmedAction()}
        onCancel={closeConfirm}
      />

      {resetPortalNode && resetDialogVisible
        ? createPortal(
          <div
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
            onClick={() => {
              if (!isPerforming) {
                closeConfirm();
              }
            }}
          >
            <div
              className="mx-4 w-full max-w-sm rounded-xl border border-border/70 bg-elevated p-6 shadow-2xl"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="mb-2 text-lg font-medium text-foreground">
                {t('settings.userManagementResetPasswordTitle')}
              </h3>
              <p className="mb-4 text-sm leading-relaxed text-secondary-text">
                {confirm.open && confirm.kind === 'reset'
                  ? `${t('settings.userManagementResetPasswordPrompt')} (${confirm.user.username})`
                  : ''}
              </p>
              <Input
                id="user-mgmt-reset-password"
                type="password"
                allowTogglePassword
                iconType="password"
                label={t('settings.userManagementNewPassword')}
                hint={t('settings.userManagementPasswordHint')}
                placeholder={t('settings.userManagementNewPasswordPlaceholder')}
                value={resetNewPassword}
                onChange={(e) => setResetNewPassword(e.target.value)}
                disabled={isPerforming}
                autoComplete="new-password"
              />
              {actionError ? (
                <div className="mt-3">
                  <ApiErrorAlert error={actionError} />
                </div>
              ) : null}
              <div className="mt-6 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={closeConfirm}
                  disabled={isPerforming}
                  className="rounded-lg border border-border/70 px-4 py-2 text-sm font-medium text-secondary-text transition-colors hover:bg-hover hover:text-foreground disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {t('settings.userManagementCancel')}
                </button>
                <button
                  type="button"
                  onClick={() => void performConfirmedAction()}
                  disabled={isPerforming || resetNewPassword.length < 6}
                  className="rounded-lg bg-cyan/80 px-4 py-2 text-sm font-medium text-foreground shadow-lg shadow-cyan/20 transition-colors hover:bg-cyan disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {isPerforming ? t('settings.userManagementSubmitting') : t('settings.userManagementSubmit')}
                </button>
              </div>
            </div>
          </div>,
          resetPortalNode,
        )
        : null}
    </SettingsSectionCard>
  );
};
