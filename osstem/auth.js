/**
 * EquipHub 인증 모듈 (auth.js)
 * - 계정 정보 및 로그인/로그아웃/권한 관리
 * - 비밀번호는 SHA-256 해시로 저장
 * - 이 파일을 별도 관리하여 보안성을 높입니다.
 */

'use strict';

// ==================== 비밀번호 해시 유틸 ====================
async function hashPassword(pw) {
  const encoder = new TextEncoder();
  const data = encoder.encode(pw + '_equiphub_salt_2024');
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ==================== 계정 데이터 (해시 비밀번호) ====================
// admin / admin1234
// user  / user1234
// 계정을 추가하려면 아래 initAccountHashes()에서 생성된 해시를 사용하세요.
const ACCOUNTS = {
  admin: {
    pwHash: '', // 초기화 시 세팅
    name: '관리자',
    role: 'admin',
    email: 'admin@equiphub.co.kr',
    department: '시스템관리팀'
  },
  user: {
    pwHash: '',
    name: '사용자',
    role: 'user',
    email: 'user@equiphub.co.kr',
    department: '서비스팀'
  }
};

// 원본 비밀번호 → 해시 변환 (초기 1회 실행)
const RAW_PASSWORDS = { admin: 'admin1234', user: 'user1234' };

async function initAccountHashes() {
  for (const [id, pw] of Object.entries(RAW_PASSWORDS)) {
    ACCOUNTS[id].pwHash = await hashPassword(pw);
  }
}

// ==================== 세션 관리 ====================
let currentUser = null; // { id, name, role, email, department, loginTime }

const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30분 자동 로그아웃
let sessionTimer = null;

function startSessionTimer() {
  clearTimeout(sessionTimer);
  sessionTimer = setTimeout(() => {
    if (currentUser) {
      showToast('세션이 만료되어 자동 로그아웃됩니다.', true);
      setTimeout(doLogout, 1500);
    }
  }, SESSION_TIMEOUT_MS);
}

function resetSessionTimer() {
  if (currentUser) startSessionTimer();
}

// 사용자 활동 감지 → 세션 연장
document.addEventListener('click', resetSessionTimer);
document.addEventListener('keydown', resetSessionTimer);

// ==================== 로그인 ====================
async function doLogin() {
  const id = document.getElementById('loginId').value.trim().toLowerCase();
  const pw = document.getElementById('loginPw').value;
  const errorEl = document.getElementById('loginError');

  // 입력값 검증
  if (!id || !pw) {
    errorEl.textContent = '아이디와 비밀번호를 모두 입력해주세요.';
    errorEl.style.display = 'block';
    return;
  }

  const acc = ACCOUNTS[id];
  if (!acc) {
    errorEl.textContent = '존재하지 않는 계정입니다.';
    errorEl.style.display = 'block';
    logAuthEvent('LOGIN_FAIL', id, '계정 없음');
    return;
  }

  const inputHash = await hashPassword(pw);
  if (inputHash !== acc.pwHash) {
    errorEl.textContent = '비밀번호가 올바르지 않습니다.';
    errorEl.style.display = 'block';
    logAuthEvent('LOGIN_FAIL', id, '비밀번호 불일치');
    return;
  }

  // 로그인 성공
  errorEl.style.display = 'none';
  currentUser = {
    id,
    name: acc.name,
    role: acc.role,
    email: acc.email,
    department: acc.department,
    loginTime: new Date().toISOString()
  };

  document.getElementById('loginOverlay').classList.add('hidden');
  document.getElementById('appBody').style.display = 'block';

  applyPermissions();
  startSessionTimer();
  logAuthEvent('LOGIN_OK', id);

  // 앱 초기화 (메인 HTML에서 정의)
  if (typeof initApp === 'function') initApp();
}

// ==================== 로그아웃 ====================
function doLogout() {
  const userId = currentUser ? currentUser.id : 'unknown';
  logAuthEvent('LOGOUT', userId);

  currentUser = null;
  clearTimeout(sessionTimer);

  document.getElementById('appBody').style.display = 'none';
  document.getElementById('loginOverlay').classList.remove('hidden');
  document.getElementById('loginId').value = '';
  document.getElementById('loginPw').value = '';
  document.getElementById('loginError').style.display = 'none';

  if (typeof showSection === 'function') showSection('dashboard');
}

// ==================== 권한 확인 ====================
function isAdmin() {
  return currentUser && currentUser.role === 'admin';
}

function isLoggedIn() {
  return currentUser !== null;
}

function getCurrentUser() {
  return currentUser ? { ...currentUser } : null;
}

function requireAdmin(actionName) {
  if (!isAdmin()) {
    showToast(`"${actionName}" 기능은 관리자만 사용할 수 있습니다.`, true);
    return false;
  }
  return true;
}

// ==================== 권한별 UI 적용 ====================
function applyPermissions() {
  if (!currentUser) return;

  const av = document.getElementById('userAvatar');
  const un = document.getElementById('userName');
  const ur = document.getElementById('userRole');

  av.textContent = currentUser.name[0];
  av.className = 'user-avatar ' + currentUser.role;
  un.textContent = currentUser.name;
  ur.textContent = isAdmin() ? 'ADMIN' : 'USER';
  ur.className = 'user-role ' + currentUser.role;

  // 관리자: 모든 기능 (수정/삭제/업로드)
  // 일반 사용자: VOC 등록만 가능, 나머지 읽기전용
  const hide = !isAdmin();

  // 업로드 영역
  const partsUpload = document.getElementById('partsUploadCard');
  const noticesUpload = document.getElementById('noticesUploadCard');
  if (partsUpload) partsUpload.style.display = hide ? 'none' : 'block';
  if (noticesUpload) noticesUpload.style.display = hide ? 'none' : 'block';

  // 관리 컬럼
  const vocAction = document.getElementById('vocActionTh');
  const partsAction = document.getElementById('partsActionTh');
  if (vocAction) vocAction.style.display = hide ? 'none' : '';
  if (partsAction) partsAction.style.display = hide ? 'none' : '';

  // 읽기전용 배지
  ['vocReadonly', 'partsReadonly', 'noticesReadonly'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = hide ? 'inline-flex' : 'none';
  });
}

// ==================== 인증 로그 ====================
const authLog = [];

function logAuthEvent(type, userId, detail) {
  const entry = {
    time: new Date().toISOString(),
    type,
    userId,
    detail: detail || '',
    ip: 'local'
  };
  authLog.push(entry);

  // 콘솔 로깅 (운영 시 서버 전송으로 교체 가능)
  const color = type === 'LOGIN_OK' ? '#4cd97b' : type === 'LOGOUT' ? '#4a9eff' : '#ff5c5c';
  console.log(
    `%c[AUTH] ${type}%c ${userId} ${detail ? '- ' + detail : ''} (${entry.time})`,
    `color:${color};font-weight:bold`, 'color:inherit'
  );
}

function getAuthLog() {
  return [...authLog];
}

// ==================== 비밀번호 변경 (관리자용) ====================
async function changePassword(userId, newPassword) {
  if (!requireAdmin('비밀번호 변경')) return false;

  if (!ACCOUNTS[userId]) {
    showToast('존재하지 않는 계정입니다.', true);
    return false;
  }

  if (newPassword.length < 6) {
    showToast('비밀번호는 6자 이상이어야 합니다.', true);
    return false;
  }

  ACCOUNTS[userId].pwHash = await hashPassword(newPassword);
  logAuthEvent('PW_CHANGE', currentUser.id, `대상: ${userId}`);
  showToast(`${userId} 계정의 비밀번호가 변경되었습니다.`);
  return true;
}

// ==================== 계정 추가 (관리자용) ====================
async function addAccount(userId, password, name, role, email, department) {
  if (!requireAdmin('계정 추가')) return false;

  if (ACCOUNTS[userId]) {
    showToast('이미 존재하는 아이디입니다.', true);
    return false;
  }

  if (!userId || !password || !name) {
    showToast('아이디, 비밀번호, 이름은 필수입니다.', true);
    return false;
  }

  ACCOUNTS[userId] = {
    pwHash: await hashPassword(password),
    name,
    role: role || 'user',
    email: email || '',
    department: department || ''
  };

  logAuthEvent('ACCOUNT_ADD', currentUser.id, `새 계정: ${userId} (${role || 'user'})`);
  showToast(`${userId} 계정이 추가되었습니다.`);
  return true;
}

// ==================== 계정 삭제 (관리자용) ====================
function removeAccount(userId) {
  if (!requireAdmin('계정 삭제')) return false;

  if (!ACCOUNTS[userId]) {
    showToast('존재하지 않는 계정입니다.', true);
    return false;
  }

  if (userId === 'admin') {
    showToast('기본 관리자 계정은 삭제할 수 없습니다.', true);
    return false;
  }

  if (currentUser && currentUser.id === userId) {
    showToast('현재 로그인한 계정은 삭제할 수 없습니다.', true);
    return false;
  }

  delete ACCOUNTS[userId];
  logAuthEvent('ACCOUNT_DEL', currentUser.id, `삭제: ${userId}`);
  showToast(`${userId} 계정이 삭제되었습니다.`);
  return true;
}

// ==================== 계정 목록 조회 (관리자용) ====================
function listAccounts() {
  if (!isAdmin()) return [];
  return Object.entries(ACCOUNTS).map(([id, acc]) => ({
    id,
    name: acc.name,
    role: acc.role,
    email: acc.email,
    department: acc.department
  }));
}

// ==================== 초기화 ====================
// 페이지 로드 시 해시 초기화
initAccountHashes();
