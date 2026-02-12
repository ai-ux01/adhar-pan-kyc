import React, { useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import Profile from './Profile';

const ProfileWrapper = () => {
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect admin users to admin panel instead of profile page
    if (user?.role === 'admin') {
      navigate('/admin', { replace: true });
    }
  }, [user, navigate]);

  // Only render profile for non-admin users
  if (user?.role === 'admin') {
    return null; // Will redirect via useEffect
  }

  return <Profile />;
};

export default ProfileWrapper;
