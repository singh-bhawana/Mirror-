export async function getSession() {
  try {
    const response = await fetch('/api/auth/me', {
      credentials: 'include'
    });
    
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    return null;
  }
}

export async function login(email: string, password: string) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include'
  });
  
  if (!response.ok) {
    const data = await response.json();
    throw new Error(data.error || 'Login failed');
  }
  
  return response.json();
}

export async function logout() {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'include'
  });
  
  if (!response.ok) {
    throw new Error('Logout failed');
  }
  
  return response.json();
} 