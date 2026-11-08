import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
/**
 * The mobile remote-control panel body: status card (state text + badge),
 * the QR code, the open-on-phone hint with the link text, and the two
 * actions (stop / refresh / copy). The advertised network is not a choice:
 * the QR names the public base and the landing page decides at connect time
 * whether to move to a LAN origin (lan-source.ts), so the panel only states
 * which source the current link carries. Pure presentation — all state and
 * actions arrive through props from the entry's behavior component.
 */
import clsx from 'clsx';
import { memo, useState } from 'react';
import { QRCodeSVG } from 'qrcode.react';
import { IconCloseOutlineRegular, IconCopyOutlineRegular, IconRefreshOutlineRegular, IconStopFillRegular, } from '@deepseek-ai/dsh-client-ui-primitives';
import { formatClock, formatLastSeen, } from "./pair-api.js";
import { deviceDisplayName, deviceNameFromUserAgent, duplicateDeviceGroups } from "./device-name.js";
import css from './remote.module.css';
/**
 * The QR symbol, memoized on the link: the panel re-renders on every SSE state
 * frame (a paired phone heartbeats every 10s), and qrcode.react rebuilds the
 * SVG path and element tree on each render.
 */
const PairQrCode = memo(function PairQrCode({ url, className }) {
    return _jsx(QRCodeSVG, { value: url, size: 184, level: "M", marginSize: 1, className: className });
});
/**
 * The authorized-device roster: a rename editor per row, the unpair action, and
 * one merge affordance per same-User-Agent group. Editing state is view state
 * local to this component (nothing here survives a remount); every mutation
 * goes through the entry's host-backed props.
 */
function DeviceRoster({ t, devices, onRevoke, onRename, onMerge, }) {
    const [editing, setEditing] = useState(null);
    const [saving, setSaving] = useState(false);
    const [renameFailed, setRenameFailed] = useState(false);
    const [mergeFailedFor, setMergeFailedFor] = useState(undefined);
    const groupsByFirst = new Map();
    for (const group of duplicateDeviceGroups(devices))
        groupsByFirst.set(group[0].id, group);
    const submitRename = async (event, deviceId) => {
        event.preventDefault();
        if (editing === null)
            return;
        setSaving(true);
        setRenameFailed(false);
        try {
            const stored = await onRename(deviceId, editing.draft);
            if (stored) {
                setEditing(null);
                return;
            }
            setRenameFailed(true);
        }
        catch {
            setRenameFailed(true);
        }
        finally {
            setSaving(false);
        }
    };
    const merge = async (groupKey, deviceIds) => {
        setMergeFailedFor(undefined);
        try {
            const merged = await onMerge(deviceIds);
            if (!merged)
                setMergeFailedFor(groupKey);
        }
        catch {
            setMergeFailedFor(groupKey);
        }
    };
    return (_jsx("ul", { className: css.deviceList, children: devices.map((device) => {
            const group = groupsByFirst.get(device.id);
            const groupKey = device.userAgent ?? device.id;
            const isEditing = editing?.id === device.id;
            return (_jsxs("li", { className: css.deviceEntry, children: [_jsxs("div", { className: css.deviceRow, children: [_jsxs("div", { className: css.deviceMeta, children: [isEditing ? (_jsxs("form", { className: css.deviceNameForm, onSubmit: (event) => { void submitRename(event, device.id); }, children: [_jsx("input", { className: css.deviceNameInput, value: editing.draft, "aria-label": t('devices.rename.label'), placeholder: deviceNameFromUserAgent(device.userAgent) ?? t('devices.unknown'), maxLength: 64, autoFocus: true, disabled: saving, onChange: (event) => { setEditing({ id: device.id, draft: event.target.value }); }, onKeyDown: (event) => { if (event.key === 'Escape')
                                                    setEditing(null); } }), _jsx("button", { type: "submit", className: css.deviceRename, disabled: saving, children: t('devices.rename.save') }), _jsx("button", { type: "button", className: css.deviceRename, disabled: saving, onClick: () => { setEditing(null); }, children: t('devices.rename.cancel') })] })) : (_jsx("span", { className: css.deviceName, title: deviceDisplayName(device, t('devices.unknown')), children: deviceDisplayName(device, t('devices.unknown')) })), _jsx("span", { className: clsx(css.devicePresence, device.online ? css.deviceOnline : css.deviceOffline), children: device.online ? t('devices.online') : t('devices.offline') }), _jsx("span", { className: css.deviceSeen, children: t('devices.lastSeen', { time: formatLastSeen(device.lastSeenAt) }) }), isEditing && renameFailed && (_jsx("span", { className: css.deviceError, role: "alert", children: t('devices.rename.failed') }))] }), _jsxs("div", { className: css.deviceActions, children: [!isEditing && (_jsx("button", { type: "button", className: css.deviceRename, onClick: () => {
                                            setRenameFailed(false);
                                            setEditing({ id: device.id, draft: device.name ?? '' });
                                        }, children: t('devices.rename') })), _jsx("button", { type: "button", className: css.deviceRevoke, "aria-label": t('devices.revoke.label'), onClick: () => { onRevoke(device.id); }, children: t('devices.revoke') })] })] }), group !== undefined && (_jsxs("div", { className: css.deviceDuplicate, children: [_jsx("span", { className: css.deviceDuplicateText, children: t('devices.duplicates', { n: group.length }) }), _jsx("button", { type: "button", className: css.deviceMerge, title: t('devices.merge.hint'), onClick: () => { void merge(groupKey, group.map(row => row.id)); }, children: t('devices.merge') })] })), mergeFailedFor === groupKey && (_jsx("span", { className: css.deviceError, role: "alert", children: t('devices.merge.failed') }))] }, device.id));
        }) }));
}
/** Badge text + tone per phase (ready states only). */
function statusOf(t, state) {
    switch (state.phase) {
        case 'connected': return { text: t('status.connected', { n: state.onlineCount }), tone: 'connected' };
        case 'disconnected': return { text: t('status.disconnected'), tone: 'disconnected' };
        case 'stopped': return { text: t('status.stopped'), tone: 'stopped' };
        case 'lan-required': return { text: t('status.lanRequired'), tone: 'stopped' };
        case 'waiting': return { text: t('status.waiting'), tone: 'waiting' };
    }
}
/**
 * Render the pairing panel.
 * @param props - copy, state, and actions.
 * @returns the panel element tree.
 */
export function RemotePanel({ t, state, copied, copiedToken, onClose, onStop, onRefresh, onCopy, onCopyToken, onRevoke, onRename, onMerge, }) {
    return (_jsxs("div", { className: css.panel, role: "dialog", "aria-modal": "true", "aria-label": t('title'), children: [_jsxs("div", { className: css.header, children: [_jsxs("div", { className: css.heading, children: [_jsx("h2", { className: css.title, children: t('title') }), _jsx("p", { className: css.subtitle, children: t('subtitle') })] }), _jsx("button", { type: "button", className: css.close, "aria-label": t('close.label'), onClick: onClose, children: _jsx(IconCloseOutlineRegular, { size: 14 }) })] }), state.kind === 'lan-required' ? (_jsxs("div", { className: css.banner, role: "alert", children: [_jsx("p", { className: css.bannerTitle, children: t('status.lanRequired') }), _jsx("p", { className: css.bannerHint, children: t('status.lanRequiredHint') })] })) : state.kind === 'loopback-required' ? (_jsxs("div", { className: css.banner, role: "alert", children: [_jsx("p", { className: css.bannerTitle, children: t('status.loopbackRequired') }), _jsx("p", { className: css.bannerHint, children: t('status.loopbackRequiredHint') })] })) : state.kind === 'unreachable' ? (_jsxs("div", { className: css.banner, role: "alert", children: [_jsx("p", { className: css.bannerTitle, children: t('status.unreachable') }), _jsx("p", { className: css.bannerHint, children: t('status.unreachableHint') })] })) : (_jsxs(_Fragment, { children: [state.posture !== undefined && state.posture.hosts.some(host => host.exposed) && (_jsxs("div", { className: css.banner, role: "alert", children: [_jsx("p", { className: css.bannerTitle, children: t('posture.exposed') }), _jsx("p", { className: css.bannerHint, children: t('posture.exposedHint', { hosts: state.posture.hosts.filter(host => host.exposed).map(host => host.host).join(', ') }) })] })), _jsxs("div", { className: css.card, children: [_jsxs("div", { className: css.cardHeader, children: [_jsx("span", { className: css.cardTitle, children: t('card.title') }), _jsxs("span", { className: css.badges, children: [state.public && _jsx("span", { className: clsx(css.badge, css.badgePublic), children: t('public.badge') }), _jsx("span", { className: clsx(css.badge, css[`badge-${statusOf(t, state).tone}`]), children: statusOf(t, state).text })] })] }), _jsx("div", { className: css.qrWrap, "data-testid": "remote-qr", children: _jsx(PairQrCode, { url: state.url, className: css.qr }) }), state.expired
                                ? _jsx("p", { className: css.expired, children: t('pair.expired') })
                                : _jsx("p", { className: css.expiry, children: t('pair.expires', { time: formatClock(state.expiresAt) }) })] }), _jsx("p", { className: css.hint, children: state.public ? t('pair.publicHint') : t('pair.hint') }), _jsxs("div", { className: css.pairLinks, children: [_jsxs("div", { className: css.pairLinkRow, children: [_jsxs("div", { className: css.pairLinkText, children: [_jsx("span", { className: css.pairLinkLabel, children: t('pair.linkLabel') }), _jsx("code", { className: css.link, title: state.url, children: state.url })] }), _jsxs("button", { type: "button", className: css.copyLink, onClick: () => onCopy(state.url), children: [_jsx(IconCopyOutlineRegular, { size: 14 }), copied ? t('action.copied') : t('action.copyLink')] })] }), state.token !== undefined && state.token !== '' && (_jsxs("div", { className: css.pairLinkRow, children: [_jsxs("div", { className: css.pairLinkText, children: [_jsx("span", { className: css.pairLinkLabel, children: t('pair.tokenLabel') }), _jsx("code", { className: css.link, title: state.token, children: state.token })] }), _jsxs("button", { type: "button", className: css.copyLink, onClick: () => onCopyToken ? onCopyToken(state.token) : onCopy(state.token), children: [_jsx(IconCopyOutlineRegular, { size: 14 }), copiedToken ? t('action.copiedToken') : t('action.copyToken')] })] }))] }), _jsxs("p", { className: css.oneTimeHint, children: [t('pair.oneTimeHint'), " ", t('pair.dockerHint')] }), state.phase === 'stopped' && _jsx("p", { className: css.stoppedHint, children: t('stopped.hint') }), state.tunnel !== undefined && state.tunnel.state !== 'running' && (_jsx("p", { className: state.tunnel.state === 'failed' ? css.tunnelFailed : css.tunnelNote, role: "status", children: state.tunnel.state === 'failed'
                            ? t('tunnel.failed', { error: state.tunnel.error ?? t('tunnel.unknownError') })
                            : t('tunnel.starting') })), state.relay?.state === 'registering' && (_jsx("p", { className: css.tunnelNote, role: "status", children: t('relay.registering') })), state.relay?.state === 'failed' && (_jsx("p", { className: css.tunnelFailed, role: "status", children: t('relay.failed', { error: state.relay.error ?? t('tunnel.unknownError') }) })), (state.publicBaseUrl !== undefined || !state.public) && (_jsx("p", { className: css.addressHint, children: state.public ? t('address.auto') : t('address.pinnedLan') })), _jsxs("div", { className: css.actions, children: [_jsxs("button", { type: "button", className: css.action, onClick: onStop, children: [_jsx(IconStopFillRegular, { size: 14 }), t('action.stop')] }), _jsxs("button", { type: "button", className: css.action, onClick: onRefresh, children: [_jsx(IconRefreshOutlineRegular, { size: 14 }), t('action.refresh')] })] }), _jsxs("section", { className: css.devices, "data-testid": "remote-devices", "aria-label": t('devices.title'), children: [_jsx("h3", { className: css.devicesTitle, children: t('devices.title') }), state.devices.length === 0 ? (_jsx("p", { className: css.devicesEmpty, children: t('devices.empty') })) : (_jsx(DeviceRoster, { t: t, devices: state.devices, onRevoke: onRevoke, onRename: onRename, onMerge: onMerge }))] })] }))] }));
}
