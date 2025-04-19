
import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { supabase, SupabaseUser } from '@/lib/supabase';
import { toast } from 'sonner';

type AuthContextType = {
  user: SupabaseUser | null;
  isLoading: boolean;
  signIn: (email: string, password: string) => Promise<{ success: boolean; error?: string }>;
  signUp: (email: string, password: string, name: string) => Promise<{ success: boolean; error?: string }>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Initialize the auth state
  useEffect(() => {
    // Get the current user session
    const initializeAuth = async () => {
      setIsLoading(true);
      try {
        const { data, error } = await supabase.auth.getSession();
        
        if (error) {
          console.error('Error getting session:', error);
          return;
        }
        
        if (data?.session) {
          const { data: userData } = await supabase.auth.getUser();
          setUser(userData.user as SupabaseUser);
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();

    // Set up auth state change listener
    const { data } = supabase.auth.onAuthStateChange(async (event, session) => {
      if (event === 'SIGNED_IN' && session) {
        const { data } = await supabase.auth.getUser();
        setUser(data.user as SupabaseUser);
      } else if (event === 'SIGNED_OUT') {
        setUser(null);
      }
    });

    // Clean up subscription
    return () => {
      data.subscription.unsubscribe();
    };
  }, []);

  // Sign in with email and password
  const signIn = async (email: string, password: string) => {
    try {
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (error) {
        // Check if the error is due to user not found or invalid credentials
        if (error.message.includes('Invalid login credentials')) {
          return { 
            success: false, 
            error: 'Account not found. Please register first.' 
          };
        }
        return { success: false, error: error.message };
      }

      // Successfully signed in
      setUser(data.user as SupabaseUser);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message || 'Authentication failed' };
    }
  };

  // Sign up with email and password
  const signUp = async (email: string, password: string, name: string) => {
    try {
      const { data, error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            name,
          },
        },
      });

      if (error) {
        return { success: false, error: error.message };
      }

      // Check if user is already registered
      if (data.user?.identities?.length === 0) {
        return { 
          success: false, 
          error: 'This email is already registered. Please sign in instead.' 
        };
      }

      // Successfully signed up
      setUser(data.user as SupabaseUser);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message || 'Registration failed' };
    }
  };

  // Sign out
  const signOut = async () => {
    await supabase.auth.signOut();
    setUser(null);
    toast.success('You have been signed out');
  };

  const value = {
    user,
    isLoading,
    signIn,
    signUp,
    signOut,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
