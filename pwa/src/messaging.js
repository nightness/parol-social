// ParolNet PWA — Message Routing, Groups, File Receive, Calls
import {
    wasm, cryptoStore, currentView, currentPeerId, setCurrentPeerId,
    currentGroupId, setCurrentGroupId, currentGroupCallId, setCurrentGroupCallId,
    incomingCallInfo, setIncomingCallInfo, localStream, setLocalStream,
    pendingFileReceives, groupCallPollInterval, setGroupCallPollInterval,
    currentCallId, setCurrentCallId
} from './state.js';
import { showToast, escapeHtml, escapeAttr, formatTime, formatSize, showLocalNotification } from './utils.js';
import { dbGet, dbPut, dbGetAll, dbGetByIndex, dbDelete } from './db.js';
import { showView } from './views.js';
import { hasDirectConnection, sendViaWebRTC, seenGossipMessages, markGossipSeen,
         handleRTCOffer, handleRTCAnswer, handleRTCIce } from './webrtc.js';
import { sendToRelay, discoverPeers, startDiscoveryInterval } from './connection.js';
import { loadContacts, appendMessage, answerIncomingCall, loadAddressBook } from './ui-chat.js';

// ── Relay Message Handling ────────────────────────────────
export function handleRelayMessage(msg) {
    switch (msg.type) {
        case 'registered':
            console.log('Registered with relay. Online peers:', msg.online_peers);
            discoverPeers();
            startDiscoveryInterval();
            break;

        case 'message':
            if (msg.payload && typeof msg.payload === 'string') {
                try {
                    const parsed = JSON.parse(msg.payload);
                    if (parsed && parsed._pn_type) {
                        handleStructuredMessage(msg.from, parsed);
                        break;
                    }
                } catch(e) {
                    // Not JSON — pass through to regular handler
                }
            }
            onIncomingMessage(msg.from, msg.payload);
            break;

        case 'queued':
            console.log('Message queued (peer offline)');
            showToast('Peer offline — message will be delivered when they connect');
            break;

        case 'rtc_offer':
            handleRTCOffer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] offer error:', e));
            break;
        case 'rtc_answer':
            handleRTCAnswer(msg.from, msg.payload).catch(e => console.warn('[WebRTC] answer error:', e));
            break;
        case 'rtc_ice':
            handleRTCIce(msg.from, msg.payload).catch(e => console.warn('[WebRTC] ICE error:', e));
            break;

        case 'error':
            console.warn('Relay error:', msg.message);
            if (msg.message === 'peer not connected') {
                showToast('Peer is not online');
            }
            break;
    }
}

function handleStructuredMessage(fromPeerId, msg) {
    switch (msg._pn_type) {
        case 'file_offer':
            handleFileOffer({ ...msg, from: fromPeerId });
            break;
        case 'file_chunk':
            handleFileChunk(msg);
            break;
        case 'file_accept':
            handleFileAccept(msg);
            break;
        case 'call_offer':
            handleIncomingCall({ ...msg, from: fromPeerId });
            break;
        case 'call_reject':
            showToast('Call declined');
            break;
        case 'group_message':
            handleIncomingGroupMessage(msg);
            break;
        case 'group_invite':
            handleGroupInvite({ ...msg, from: fromPeerId });
            break;
        case 'group_call_invite':
            handleGroupCallInvite({ ...msg, from: fromPeerId });
            break;
        case 'group_file_offer':
            handleGroupFileOffer(msg);
            break;
        case 'group_file_chunk':
            handleGroupFileChunk(msg);
            break;
        case 'sender_key':
            handleSenderKey(msg, fromPeerId);
            break;
        default:
            console.warn('[Structured] Unknown message type:', msg._pn_type);
    }
}

// ── Group Management ───────────────────────────────────────

export function switchListTab(tab) {
    document.querySelectorAll('.list-tab').forEach(t => t.classList.remove('active'));
    const btn = document.querySelector(`.list-tab[data-list="${tab}"]`);
    if (btn) btn.classList.add('active');
    const contactList = document.getElementById('contact-list');
    const groupList = document.getElementById('group-list');
    const addressBookList = document.getElementById('address-book-list');
    const createGroupBtn = document.getElementById('create-group-btn');
    if (contactList) contactList.classList.add('hidden');
    if (groupList) groupList.classList.add('hidden');
    if (addressBookList) addressBookList.classList.add('hidden');
    if (createGroupBtn) createGroupBtn.classList.add('hidden');
    if (tab === 'groups') {
        if (groupList) groupList.classList.remove('hidden');
        if (createGroupBtn) createGroupBtn.classList.remove('hidden');
        loadGroups();
    } else if (tab === 'address-book') {
        if (addressBookList) addressBookList.classList.remove('hidden');
        loadAddressBook();
    } else {
        if (contactList) contactList.classList.remove('hidden');
        loadContacts();
    }
}

export async function loadGroups() {
    try {
        const groups = await dbGetAll('groups');
        renderGroupList(groups);
    } catch (e) {
        console.warn('Failed to load groups:', e);
        renderGroupList([]);
    }
}

function renderGroupList(groups) {
    const list = document.getElementById('group-list');
    if (!list) return;
    if (!groups || groups.length === 0) {
        list.innerHTML = '<div class="empty-state"><p>No groups yet</p><p>Create or join a group</p></div>';
        return;
    }
    list.innerHTML = groups.map(g => `
        <div class="contact-item" onclick="openGroupChat('${escapeAttr(g.groupId)}')">
            <div class="contact-avatar">${escapeHtml((g.name || 'G')[0].toUpperCase())}</div>
            <div class="contact-info">
                <div class="contact-name" dir="auto">${escapeHtml(g.name || 'Unnamed Group')}</div>
                <div class="contact-last-msg" dir="auto">${escapeHtml(g.lastMessage || 'No messages yet')}</div>
            </div>
            <div class="contact-meta">
                <div class="contact-time">${escapeHtml(g.lastTime || '')}</div>
            </div>
        </div>
    `).join('');
}

export function showCreateGroupDialog() {
    showView('create-group');
    const nameInput = document.getElementById('create-group-name');
    if (nameInput) { nameInput.value = ''; nameInput.focus(); }
}

export async function createGroup() {
    const nameInput = document.getElementById('create-group-name');
    if (!nameInput) return;
    const name = nameInput.value.trim();
    if (!name) { showToast('Enter a group name'); return; }
    const groupId = 'grp-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
    const myPeerId = window._peerId || '';
    const group = {
        groupId,
        name,
        members: [myPeerId],
        createdBy: myPeerId,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        if (wasm && wasm.create_sender_key) {
            try { wasm.create_sender_key(groupId); } catch(e) { console.warn('[Group] Sender key init:', e); }
        }
        showToast('Group created');
        openGroupChat(groupId);
    } catch (e) {
        showToast('Failed to create group');
        console.error('[Group] Create failed:', e);
    }
}

export async function openGroupChat(groupId) {
    setCurrentGroupId(groupId);
    showView('group-chat');
    const group = await dbGet('groups', groupId);
    const nameEl = document.getElementById('group-chat-name');
    if (nameEl) nameEl.textContent = group ? group.name : groupId.slice(0, 12);
    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl && group) badgeEl.textContent = (group.members || []).length;
    await loadGroupMessages(groupId);
}

async function loadGroupMessages(groupId) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    try {
        const messages = await dbGetByIndex('group_messages', 'groupId', groupId);
        messages.sort((a, b) => a.timestamp - b.timestamp);
        container.innerHTML = '';
        for (const m of messages) {
            appendGroupMessage(m);
        }
        container.scrollTop = container.scrollHeight;
    } catch (e) {
        console.warn('Failed to load group messages:', e);
        container.innerHTML = '';
    }
}

export function appendGroupMessage(msg) {
    const container = document.getElementById('group-message-list');
    if (!container) return;
    const myPeerId = window._peerId || '';
    const isMine = msg.sender === myPeerId;
    const div = document.createElement('div');
    div.className = `message ${isMine ? 'sent' : 'received'}`;
    if (!isMine) {
        const senderLabel = document.createElement('div');
        senderLabel.className = 'group-msg-sender';
        senderLabel.textContent = (msg.sender || '').slice(0, 8) + '...';
        div.appendChild(senderLabel);
    }
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    if (msg.domContent) {
        bubble.appendChild(msg.domContent);
    } else {
        bubble.setAttribute('dir', 'auto');
        bubble.textContent = msg.content || '';
    }
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(msg.timestamp);
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

export async function sendGroupMessage() {
    const input = document.getElementById('group-message-input');
    if (!input) return;
    const text = input.value.trim();
    if (!text || !currentGroupId) return;

    const myPeerId = window._peerId || '';
    const msg = {
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: Date.now()
    };

    try { await dbPut('group_messages', msg); } catch(e) { console.warn(e); }
    appendGroupMessage(msg);
    input.value = '';

    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const payload = JSON.stringify({
        _pn_type: 'group_message',
        groupId: currentGroupId,
        sender: myPeerId,
        content: text,
        timestamp: msg.timestamp
    });
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        if (hasDirectConnection(memberId)) {
            sendViaWebRTC(memberId, payload);
        } else {
            sendToRelay(memberId, payload);
        }
    }

    group.lastMessage = text.slice(0, 50);
    group.lastTime = formatTime(Date.now());
    try { await dbPut('groups', group); } catch(e) {}
}

async function handleIncomingGroupMessage(msg) {
    if (!msg.groupId) return;
    const stored = {
        groupId: msg.groupId,
        sender: msg.sender || '',
        content: msg.content || '',
        timestamp: msg.timestamp || Date.now()
    };
    try { await dbPut('group_messages', stored); } catch(e) { console.warn(e); }

    try {
        const group = await dbGet('groups', msg.groupId);
        if (group) {
            group.lastMessage = (msg.content || '').slice(0, 50);
            group.lastTime = formatTime(Date.now());
            await dbPut('groups', group);
        }
    } catch(e) {}

    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        appendGroupMessage(stored);
    } else {
        showToast('New group message');
        showLocalNotification('Group Message', (msg.content || '').slice(0, 100), msg.groupId);
    }
}

export async function showGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (!modal || !currentGroupId) return;
    modal.classList.remove('hidden');

    const group = await dbGet('groups', currentGroupId);
    const memberList = document.getElementById('group-members-list');
    if (!memberList || !group) return;
    const myPeerId = window._peerId || '';
    const isCreator = group.createdBy === myPeerId;

    memberList.innerHTML = (group.members || []).map(memberId => {
        const isMe = memberId === myPeerId;
        const shortId = memberId.slice(0, 12) + '...';
        const role = memberId === group.createdBy ? 'Creator' : 'Member';
        const removeBtn = isCreator && !isMe
            ? `<button class="group-member-remove" onclick="removeMemberFromGroup('${escapeAttr(memberId)}')">Remove</button>`
            : '';
        return `
            <div class="group-member-item">
                <div>
                    <div class="group-member-name">${escapeHtml(shortId)}${isMe ? ' (You)' : ''}</div>
                    <div class="group-member-role">${role}</div>
                </div>
                ${removeBtn}
            </div>
        `;
    }).join('');
}

export function closeGroupMembers() {
    const modal = document.getElementById('group-members-modal');
    if (modal) modal.classList.add('hidden');
}

export async function addMemberFromInput() {
    const input = document.getElementById('add-member-input');
    if (!input) return;
    const peerId = input.value.trim();
    if (!peerId) { showToast('Enter a peer ID'); return; }
    await addMemberToGroup(peerId);
    input.value = '';
}

export async function addMemberToGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    if (group.members.includes(peerId)) { showToast('Already a member'); return; }
    group.members.push(peerId);
    await dbPut('groups', group);

    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    const payload = JSON.stringify({
        _pn_type: 'group_invite',
        groupId: group.groupId,
        groupName: group.name,
        members: group.members
    });
    sendToRelay(peerId, payload);

    if (wasm && wasm.create_sender_key) {
        try {
            const keyData = wasm.create_sender_key(currentGroupId);
            if (keyData) {
                const skPayload = JSON.stringify({
                    _pn_type: 'sender_key',
                    groupId: currentGroupId,
                    keyData: Array.from(new Uint8Array(keyData))
                });
                sendToRelay(peerId, skPayload);
            }
        } catch(e) { console.warn('[Group] Sender key distribution:', e); }
    }

    showToast('Member added');
    showGroupMembers();
}

export async function removeMemberFromGroup(peerId) {
    if (!currentGroupId || !peerId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    group.members = group.members.filter(m => m !== peerId);
    await dbPut('groups', group);

    const badgeEl = document.getElementById('group-member-count');
    if (badgeEl) badgeEl.textContent = group.members.length;

    showToast('Member removed');
    showGroupMembers();
}

export async function leaveCurrentGroup() {
    if (!currentGroupId) return;
    try { await dbDelete('groups', currentGroupId); } catch(e) {}
    setCurrentGroupId(null);
    closeGroupMembers();
    showView('contacts');
    switchListTab('groups');
    showToast('Left group');
}

async function handleGroupInvite(msg) {
    if (!msg.groupId || !msg.groupName) return;
    const myPeerId = window._peerId || '';
    const group = {
        groupId: msg.groupId,
        name: msg.groupName,
        members: msg.members || [msg.from, myPeerId],
        createdBy: msg.from,
        createdAt: Date.now(),
        lastMessage: '',
        lastTime: ''
    };
    try {
        await dbPut('groups', group);
        showToast('Invited to group: ' + msg.groupName);
        if (currentView === 'contacts') loadGroups();
    } catch(e) {
        console.warn('[Group] Invite save failed:', e);
    }
}

function handleSenderKey(msg, fromPeerId) {
    if (!msg.groupId || !msg.keyData) return;
    if (wasm && wasm.receive_sender_key) {
        try {
            const keyBytes = new Uint8Array(msg.keyData);
            wasm.receive_sender_key(msg.groupId, fromPeerId, keyBytes);
            console.log('[Group] Received sender key for', msg.groupId, 'from', fromPeerId.slice(0, 8));
        } catch(e) {
            console.warn('[Group] Sender key receive failed:', e);
        }
    }
}

// ── File Receive Flow ──────────────────────────────────────

function handleFileOffer(msg) {
    if (!msg.from || !msg.fileId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.from,
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: false
    };
    if (currentView === 'chat' && currentPeerId === msg.from) {
        showFileOfferInChat(msg);
    } else {
        showToast('File offered: ' + (msg.fileName || 'file'));
        showLocalNotification('File Offer', msg.fileName || 'file', msg.from);
    }
}

function showFileOfferInChat(msg) {
    const container = document.getElementById('message-list');
    if (!container) return;
    const div = document.createElement('div');
    div.className = 'message received';
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    const offer = document.createElement('div');
    offer.className = 'file-offer';
    offer.id = 'file-offer-' + msg.fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-offer-name';
    nameEl.textContent = msg.fileName || 'file';
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-offer-size';
    sizeEl.textContent = formatSize(msg.fileSize || 0);
    const actions = document.createElement('div');
    actions.className = 'file-offer-actions';
    const acceptBtn = document.createElement('button');
    acceptBtn.textContent = 'Accept';
    acceptBtn.className = 'call-action-btn accept';
    acceptBtn.onclick = () => acceptFileOffer(msg.fileId);
    const declineBtn = document.createElement('button');
    declineBtn.textContent = 'Decline';
    declineBtn.className = 'call-action-btn decline';
    declineBtn.onclick = () => declineFileOffer(msg.fileId);
    actions.appendChild(acceptBtn);
    actions.appendChild(declineBtn);
    offer.appendChild(nameEl);
    offer.appendChild(sizeEl);
    offer.appendChild(actions);
    bubble.appendChild(offer);
    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = formatTime(Date.now());
    div.appendChild(bubble);
    div.appendChild(time);
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

export function acceptFileOffer(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    pending.accepted = true;
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Receiving... 0%</div>';
    }
    const payload = JSON.stringify({ _pn_type: 'file_accept', fileId });
    sendToRelay(pending.from, payload);
}

export function declineFileOffer(fileId) {
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        const actions = offerEl.querySelector('.file-offer-actions');
        if (actions) actions.innerHTML = '<div class="file-status">Declined</div>';
    }
    delete pendingFileReceives[fileId];
}

function handleFileAccept(msg) {
    if (!msg.fileId) return;
    console.log('[File] Peer accepted file:', msg.fileId);
    if (wasm && wasm.get_next_chunk) {
        sendFileChunked(msg.fileId, msg.from || currentPeerId);
    }
}

function handleFileChunk(msg) {
    const pending = pendingFileReceives[msg.fileId];
    if (!pending || !pending.accepted) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

function offerDownload(fileId) {
    const pending = pendingFileReceives[fileId];
    if (!pending) return;
    const parts = [];
    for (let i = 0; i < pending.totalChunks; i++) {
        if (pending.chunks[i]) {
            const bytes = new Uint8Array(pending.chunks[i]);
            parts.push(bytes);
        }
    }
    const blob = new Blob(parts);
    const url = URL.createObjectURL(blob);
    const offerEl = document.getElementById('file-offer-' + fileId);
    if (offerEl) {
        offerEl.innerHTML = '';
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = pending.name;
        const link = document.createElement('a');
        link.className = 'file-download-link';
        link.href = url;
        link.download = pending.name;
        link.textContent = 'Download (' + formatSize(pending.size) + ')';
        offerEl.appendChild(nameEl);
        offerEl.appendChild(link);
    }
    delete pendingFileReceives[fileId];
}

async function sendFileChunked(fileId, toPeerId) {
    if (!toPeerId) return;
    const CHUNK_SIZE = 16384;
    let chunkIndex = 0;
    if (wasm && wasm.get_next_chunk) {
        while (true) {
            try {
                const chunk = wasm.get_next_chunk(fileId);
                if (!chunk || chunk.length === 0) break;
                const payload = JSON.stringify({
                    _pn_type: 'file_chunk',
                    fileId,
                    chunkIndex,
                    totalChunks: -1,
                    data: Array.from(chunk)
                });
                if (hasDirectConnection(toPeerId)) {
                    sendViaWebRTC(toPeerId, payload);
                } else {
                    sendToRelay(toPeerId, payload);
                }
                chunkIndex++;
                if (chunkIndex % 10 === 0) {
                    await new Promise(r => setTimeout(r, 0));
                }
            } catch(e) {
                console.warn('[File] Chunk send error:', e);
                break;
            }
        }
    }
}

// ── Incoming Call Notification ──────────────────────────────

function handleIncomingCall(msg) {
    setIncomingCallInfo({ from: msg.from, callId: msg.callId });
    showIncomingCallNotification(msg.from, msg.callId);
}

function showIncomingCallNotification(fromPeerId, callId) {
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = fromPeerId.slice(0, 12) + '...';
    notif.classList.remove('hidden');
    showLocalNotification('Incoming Call', 'Call from ' + fromPeerId.slice(0, 12), fromPeerId);
}

export function acceptIncomingCall() {
    if (!incomingCallInfo) return;
    if (incomingCallInfo.isGroup) {
        joinGroupCall();
        return;
    }
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    setCurrentPeerId(incomingCallInfo.from);
    setCurrentCallId(incomingCallInfo.callId);
    answerIncomingCall(incomingCallInfo.callId);
    showView('call');
    const nameEl = document.getElementById('call-peer-name');
    if (nameEl) nameEl.textContent = incomingCallInfo.from.slice(0, 16) + '...';
    setIncomingCallInfo(null);
}

export function declineIncomingCall() {
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    if (!incomingCallInfo) return;
    const payload = JSON.stringify({ _pn_type: 'call_reject', callId: incomingCallInfo.callId });
    sendToRelay(incomingCallInfo.from, payload);
    setIncomingCallInfo(null);
}

// ── Group Calls ────────────────────────────────────────────

export async function startGroupCall() {
    if (!currentGroupId) return;
    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const callId = 'gcall-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
    setCurrentGroupCallId(callId);

    try {
        setLocalStream(await navigator.mediaDevices.getUserMedia({ audio: true }));
    } catch(e) {
        showToast('Could not access microphone: ' + e.message);
        return;
    }

    showGroupCallView(group.name, group.members);

    const myPeerId = window._peerId || '';
    const payload = JSON.stringify({
        _pn_type: 'group_call_invite',
        groupId: currentGroupId,
        callId,
        groupName: group.name
    });
    for (const memberId of (group.members || [])) {
        if (memberId === myPeerId) continue;
        sendToRelay(memberId, payload);
    }
}

function showGroupCallView(groupName, members) {
    showView('group-call');
    const nameEl = document.getElementById('group-call-name');
    if (nameEl) nameEl.textContent = groupName || 'Group Call';

    const grid = document.getElementById('group-call-grid');
    if (!grid) return;
    grid.innerHTML = '';
    const myPeerId = window._peerId || '';

    const selfTile = document.createElement('div');
    selfTile.className = 'group-call-tile';
    selfTile.id = 'gcall-tile-self';
    const selfName = document.createElement('div');
    selfName.className = 'group-call-tile-name';
    selfName.textContent = 'You';
    selfTile.appendChild(selfName);
    grid.appendChild(selfTile);

    for (const memberId of (members || [])) {
        if (memberId === myPeerId) continue;
        if (grid.children.length >= 8) break;
        const tile = document.createElement('div');
        tile.className = 'group-call-tile';
        tile.id = 'gcall-tile-' + memberId.slice(0, 12);
        const tileName = document.createElement('div');
        tileName.className = 'group-call-tile-name';
        tileName.textContent = memberId.slice(0, 8) + '...';
        tile.appendChild(tileName);
        grid.appendChild(tile);
    }
}

function handleGroupCallInvite(msg) {
    if (!msg.groupId || !msg.callId) return;
    setIncomingCallInfo({ from: msg.from, callId: msg.callId, isGroup: true, groupId: msg.groupId, groupName: msg.groupName });
    const notif = document.getElementById('incoming-call-notification');
    if (!notif) return;
    const nameEl = document.getElementById('incoming-call-name');
    if (nameEl) nameEl.textContent = (msg.groupName || 'Group') + ' call';
    const labelEl = document.getElementById('incoming-call-label');
    if (labelEl) labelEl.textContent = 'Group call invitation';
    notif.classList.remove('hidden');
    showLocalNotification('Group Call', (msg.groupName || 'Group') + ' call', msg.from);
}

export async function joinGroupCall() {
    if (!incomingCallInfo || !incomingCallInfo.isGroup) return;
    const notif = document.getElementById('incoming-call-notification');
    if (notif) notif.classList.add('hidden');
    setCurrentGroupCallId(incomingCallInfo.callId);
    setCurrentGroupId(incomingCallInfo.groupId);

    try {
        setLocalStream(await navigator.mediaDevices.getUserMedia({ audio: true }));
    } catch(e) {
        showToast('Could not access microphone: ' + e.message);
        setIncomingCallInfo(null);
        return;
    }

    const group = await dbGet('groups', incomingCallInfo.groupId);
    showGroupCallView(incomingCallInfo.groupName || (group ? group.name : 'Group'), group ? group.members : [incomingCallInfo.from]);
    setIncomingCallInfo(null);
}

export function leaveGroupCallUI() {
    if (localStream) {
        localStream.getTracks().forEach(t => t.stop());
        setLocalStream(null);
    }
    if (groupCallPollInterval) {
        clearInterval(groupCallPollInterval);
        setGroupCallPollInterval(null);
    }
    setCurrentGroupCallId(null);
    showView(currentGroupId ? 'group-chat' : 'contacts');
}

export function toggleGroupMute() {
    if (!localStream) return;
    const audioTrack = localStream.getAudioTracks()[0];
    if (audioTrack) {
        audioTrack.enabled = !audioTrack.enabled;
        const btn = document.querySelector('.group-call-controls .call-control-btn:first-child');
        if (btn) btn.textContent = audioTrack.enabled ? 'Mute' : 'Unmute';
    }
}

// ── Group File Transfer ────────────────────────────────────

export function attachGroupFile() {
    const input = document.getElementById('group-file-input');
    if (input) input.click();
}

export async function onGroupFileSelected(event) {
    const file = event.target.files[0];
    if (!file || !currentGroupId) return;
    event.target.value = '';

    const group = await dbGet('groups', currentGroupId);
    if (!group) return;
    const myPeerId = window._peerId || '';
    const fileId = 'gf-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);

    const msgEl = document.createElement('div');
    msgEl.className = 'file-transfer';
    msgEl.id = 'gfile-' + fileId;
    const nameEl = document.createElement('div');
    nameEl.className = 'file-name';
    nameEl.textContent = '\uD83D\uDCCE ' + file.name;
    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-size';
    sizeEl.textContent = formatSize(file.size);
    const statusEl = document.createElement('div');
    statusEl.className = 'file-status';
    statusEl.textContent = 'Sending to group...';
    msgEl.appendChild(nameEl);
    msgEl.appendChild(sizeEl);
    msgEl.appendChild(statusEl);
    appendGroupMessage({ sender: myPeerId, domContent: msgEl, timestamp: Date.now(), groupId: currentGroupId });

    try {
        const buffer = await file.arrayBuffer();
        const data = new Uint8Array(buffer);
        const CHUNK_SIZE = 16384;
        const totalChunks = Math.ceil(data.length / CHUNK_SIZE);

        for (const memberId of (group.members || [])) {
            if (memberId === myPeerId) continue;
            const offerPayload = JSON.stringify({
                _pn_type: 'group_file_offer',
                groupId: currentGroupId,
                fileId,
                fileName: file.name,
                fileSize: file.size,
                totalChunks,
                sender: myPeerId
            });
            sendToRelay(memberId, offerPayload);

            for (let i = 0; i < totalChunks; i++) {
                const chunk = data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                const chunkPayload = JSON.stringify({
                    _pn_type: 'group_file_chunk',
                    groupId: currentGroupId,
                    fileId,
                    chunkIndex: i,
                    totalChunks,
                    data: Array.from(chunk)
                });
                if (hasDirectConnection(memberId)) {
                    sendViaWebRTC(memberId, chunkPayload);
                } else {
                    sendToRelay(memberId, chunkPayload);
                }
                if (i % 10 === 0 && i > 0) {
                    await new Promise(r => setTimeout(r, 0));
                }
            }
        }
        statusEl.textContent = 'Sent';
    } catch(e) {
        statusEl.textContent = 'Failed: ' + e.message;
        console.error('[GroupFile] Send failed:', e);
    }
}

function handleGroupFileOffer(msg) {
    if (!msg.fileId || !msg.groupId) return;
    pendingFileReceives[msg.fileId] = {
        from: msg.sender || '',
        name: msg.fileName || 'file',
        size: msg.fileSize || 0,
        totalChunks: msg.totalChunks || 1,
        chunksReceived: 0,
        chunks: [],
        accepted: true,
        isGroup: true,
        groupId: msg.groupId
    };
    if (currentView === 'group-chat' && currentGroupId === msg.groupId) {
        const offerDiv = document.createElement('div');
        offerDiv.className = 'file-offer';
        offerDiv.id = 'file-offer-' + msg.fileId;
        const nameEl = document.createElement('div');
        nameEl.className = 'file-offer-name';
        nameEl.textContent = msg.fileName || 'file';
        const sizeEl = document.createElement('div');
        sizeEl.className = 'file-offer-size';
        sizeEl.textContent = formatSize(msg.fileSize || 0);
        const statusEl = document.createElement('div');
        statusEl.className = 'file-status';
        statusEl.textContent = 'Receiving... 0%';
        offerDiv.appendChild(nameEl);
        offerDiv.appendChild(sizeEl);
        offerDiv.appendChild(statusEl);
        appendGroupMessage({
            sender: msg.sender || '',
            domContent: offerDiv,
            timestamp: Date.now(),
            groupId: msg.groupId
        });
    }
}

function handleGroupFileChunk(msg) {
    const pending = pendingFileReceives[msg.fileId];
    if (!pending) return;
    pending.chunks[msg.chunkIndex] = msg.data;
    pending.chunksReceived++;
    const pct = Math.round((pending.chunksReceived / pending.totalChunks) * 100);
    const offerEl = document.getElementById('file-offer-' + msg.fileId);
    if (offerEl) {
        const status = offerEl.querySelector('.file-status');
        if (status) status.textContent = 'Receiving... ' + pct + '%';
    }
    if (pending.chunksReceived >= pending.totalChunks) {
        offerDownload(msg.fileId);
    }
}

// ── Incoming Message Handler ──────────────────────────────

export function onIncomingMessage(fromPeerId, payload) {
    if (!fromPeerId || !payload) return;

    // Dedup
    const dedupKey = fromPeerId + ':' + (typeof payload === 'string' ? payload.slice(0, 64) : '');
    if (seenGossipMessages.has(dedupKey)) return;
    markGossipSeen(dedupKey);

    // Handle system events
    if (typeof payload === 'string' && payload.startsWith('__system:')) {
        console.log('[System]', fromPeerId.slice(0, 8), payload);
        if (payload === '__system:contact_added') {
            dbPut('contacts', {
                peerId: fromPeerId,
                name: fromPeerId.slice(0, 8) + '...',
                lastMessage: '',
                lastTime: formatTime(Date.now()),
                unread: 0
            }).then(() => {
                showToast('New contact: ' + fromPeerId.slice(0, 8) + '...');
                loadContacts();
            }).catch(() => {});
        } else if (payload.startsWith('__system:bootstrap:')) {
            const theirIkHex = payload.slice('__system:bootstrap:'.length);
            if (wasm && wasm.complete_bootstrap_as_presenter && theirIkHex.length === 64) {
                try {
                    const result = wasm.complete_bootstrap_as_presenter(theirIkHex);
                    console.log('[Bootstrap] Responder session established for:', result.peer_id);
                    dbPut('contacts', {
                        peerId: result.peer_id,
                        name: result.peer_id.slice(0, 8) + '...',
                        lastMessage: 'Encrypted session established',
                        lastTime: formatTime(Date.now()),
                        unread: 0
                    }).then(async () => {
                        showToast('Secure contact: ' + result.peer_id.slice(0, 8) + '...');
                        loadContacts();
                    }).catch(() => {});
                } catch(e) {
                    console.warn('[Bootstrap] Failed to complete presenter bootstrap:', e);
                }
            }
        }
        return;
    }

    // Attempt decryption
    let messageText = payload;
    if (typeof payload === 'string' && payload.startsWith('enc:')) {
        if (wasm && wasm.decrypt_message) {
            try {
                const hexCiphertext = payload.slice(4);
                const cipherBytes = new Uint8Array(hexCiphertext.match(/.{1,2}/g).map(b => parseInt(b, 16)));
                const plainBytes = wasm.decrypt_message(fromPeerId, cipherBytes);
                const decoder = new TextDecoder();
                messageText = decoder.decode(plainBytes);
            } catch (e) {
                console.error('[Decrypt] Failed to decrypt from', fromPeerId.slice(0, 8), e);
                messageText = '[Encrypted message — decryption failed]';
            }
        } else {
            messageText = '[Encrypted message — WASM not available]';
        }
    }

    const msg = {
        peerId: fromPeerId,
        direction: 'received',
        content: messageText,
        timestamp: Date.now()
    };

    dbPut('messages', msg).catch(e => console.warn('Failed to store message:', e));

    dbPut('contacts', {
        peerId: fromPeerId,
        name: fromPeerId.slice(0, 8) + '...',
        lastMessage: messageText.slice(0, 50),
        lastTime: formatTime(Date.now()),
        unread: 1
    }).catch(() => {});

    if (currentView === 'chat' && currentPeerId === fromPeerId) {
        appendMessage(msg);
    } else {
        showLocalNotification('New Message', messageText.slice(0, 100), fromPeerId);
        showToast('Message from ' + fromPeerId.slice(0, 8) + '...');
        if (currentView === 'contacts') {
            loadContacts();
        }
    }
}
