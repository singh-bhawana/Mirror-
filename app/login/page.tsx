'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ 
          email: email.trim().toLowerCase(), 
          password: password.trim() 
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Login failed');
      }

      // Verify the cookie was set by checking auth status
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Verify authentication before redirect
      const verifyResponse = await fetch('/api/auth/me', {
        credentials: 'include'
      });
      
      if (verifyResponse.ok) {
        // Use window.location for a hard redirect to ensure cookie is read
        window.location.href = '/';
      } else {
        throw new Error('Authentication verification failed. Please try again.');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen relative flex items-center justify-center">
      <div className="gradient-bg fixed inset-0 pointer-events-none" />
      
      <div className="w-full max-w-md p-8">
        <Link href="/" className="flex items-center justify-center gap-2 mb-8">
          <div className="text-3xl font-bold text-white flex items-center">
            <svg width="32" height="32" viewBox="0 0 24 24" className="mr-2">
              <circle cx="12" cy="12" r="12" fill="#9747FF"/>
              <path d="M8 12a4 4 0 018 0" stroke="white" strokeWidth="2" strokeLinecap="round"/>
            </svg>
            Reveal the Real
          </div>
        </Link>

        <form onSubmit={handleSubmit} className="card space-y-4">
          <h1 className="text-2xl font-bold text-center mb-6">Welcome Back</h1>
          
          <div className="bg-purple-500/20 border border-purple-500/50 text-purple-200 rounded-lg p-3 text-xs mb-2">
            <strong>Demo Credentials:</strong><br />
            Email: demo@example.com<br />
            Password: demo123
          </div>
          
          {error && (
            <div className="bg-red-500/20 border border-red-500/50 text-red-200 rounded-lg p-3 text-sm">
              {error}
            </div>
          )}

          <div className="space-y-2">
            <label htmlFor="email" className="block text-sm font-medium text-gray-300">
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-white/10 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder="Enter your email"
              required
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="password" className="block text-sm font-medium text-gray-300">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-white/10 rounded-lg px-3 py-2 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
              placeholder="Enter your password"
              required
            />
          </div>

          <button
            type="submit"
            className="btn-primary w-full"
            disabled={loading}
          >
            {loading ? 'Signing in...' : 'Sign in'}
          </button>
        </form>
      </div>
    </main>
  );
} 