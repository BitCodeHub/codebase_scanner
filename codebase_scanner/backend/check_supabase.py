#!/usr/bin/env python3
"""Check Supabase client version and parameters"""

import sys
import inspect

try:
    import supabase
    print(f"Supabase version: {supabase.__version__ if hasattr(supabase, '__version__') else 'Unknown'}")
    
    from supabase import create_client
    sig = inspect.signature(create_client)
    print(f"\ncreate_client signature: {sig}")
    print(f"Parameters: {list(sig.parameters.keys())}")
    
    # Check if Client class has proxy parameter
    from supabase import Client
    client_sig = inspect.signature(Client.__init__)
    print(f"\nClient.__init__ signature: {client_sig}")
    print(f"Client parameters: {list(client_sig.parameters.keys())}")
    
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)