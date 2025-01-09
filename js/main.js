// Core state
let currentUsername = 'anonymous';

// Main functions
async function loadMessages() {
    try {
        const response = await fetch('/messages');
        const messages = await response.json();
        displayMessages(messages);
    } catch (error) {
        console.error('Error loading messages:', error);
    }
}

function displayMessages(messages) {
    const container = document.getElementById('messages-container');
    container.innerHTML = messages.map(message => `
        <div class="message">
            <div class="message-meta">
                <strong>${escapeHtml(message.author)}</strong>
                <span>${new Date(message.date).toLocaleString()}</span>
            </div>
            <div class="message-content">${escapeHtml(message.content)}</div>
        </div>
    `).join('');
    container.scrollTop = container.scrollHeight;
}

async function sendMessage(content, type = 'message') {
    try {
        const response = await fetch('/messages', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ content, type, author: currentUsername })
        });
        if (!response.ok) throw new Error('Failed to send message');
        await loadMessages();
        return true;
    } catch (error) {
        console.error('Error sending message:', error);
        return false;
    }
}

async function changeUsername(newUsername) {
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUsername)) {
        alert('Invalid username format. Use 3-20 characters: letters, numbers, underscore');
        return false;
    }
    
    const content = {
        old_username: currentUsername,
        new_username: newUsername
    };
    
    const success = await sendMessage(JSON.stringify(content), 'username_change');
    if (success) {
        currentUsername = newUsername;
        localStorage.setItem('username', newUsername);
        document.getElementById('current-username').textContent = `Current username: ${newUsername}`;
    }
    return success;
}

function setupEventListeners() {
    // Message form
    document.querySelector('.message-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const textarea = e.target.querySelector('textarea');
        const content = textarea.value.trim();
        if (content) {
            if (await sendMessage(content)) {
                textarea.value = '';
            }
        }
    });

    // Username change button
    document.getElementById('change-username-btn').addEventListener('click', () => {
        const newUsername = prompt('Enter new username:');
        if (newUsername) changeUsername(newUsername);
    });

    // Add js class to body
    document.body.classList.add('js');
}

// Utility functions
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Load saved username
    const savedUsername = localStorage.getItem('username');
    if (savedUsername) {
        currentUsername = savedUsername;
        document.getElementById('current-username').textContent = `Current username: ${savedUsername}`;
    }
    
    loadMessages();
    setupEventListeners();
    
    // Set up periodic refresh
    setInterval(loadMessages, 5000);
});
