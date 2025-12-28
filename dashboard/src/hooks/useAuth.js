import { useQuery } from '@tanstack/react-query';

export function useAuth() {
  const { data: user, isLoading } = useQuery({
    queryKey: ['/api/auth/user'],
    queryFn: async () => {
      const response = await fetch('/api/auth/user');
      if (!response.ok) {
        throw new Error(`${response.status}: ${response.statusText}`);
      }
      return response.json();
    },
    retry: false,
  });

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
  };
}