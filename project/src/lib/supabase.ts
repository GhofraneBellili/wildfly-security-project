import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export type Profile = {
  id: string;
  email: string;
  role: 'business' | 'buyer';
  business_name?: string;
  created_at: string;
};

export type Product = {
  id: string;
  business_id: string;
  title: string;
  description: string;
  price: number;
  type: 'product' | 'service';
  image_url?: string;
  created_at: string;
  updated_at: string;
};

export type Order = {
  id: string;
  buyer_id: string;
  product_id: string;
  quantity: number;
  total_price: number;
  status: 'pending' | 'completed' | 'cancelled';
  created_at: string;
};
