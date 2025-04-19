
import { createClient } from '@supabase/supabase-js';

// Using the direct URL and key instead of environment variables
const supabaseUrl = 'https://mpepojevzyhepyhshdgl.supabase.co';
const supabaseAnonKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1wZXBvamV2enloZXB5aHNoZGdsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDQ3ODA3MjQsImV4cCI6MjA2MDM1NjcyNH0.BWr55hph3tfDWuv0lbxo-cDSJdUCoKqvBQmHBIkx8-o';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export type SupabaseUser = {
  id: string;
  email?: string;
  user_metadata?: {
    name?: string;
  };
};
