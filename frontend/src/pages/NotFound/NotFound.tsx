import React from 'react';
import { Link } from 'react-router-dom';
import { HomeIcon } from '@heroicons/react/24/outline';

const NotFound: React.FC = () => {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="mx-auto h-24 w-24 text-gray-400">
          <HomeIcon className="h-full w-full" />
        </div>
        <h1 className="mt-6 text-3xl font-bold text-gray-900">404</h1>
        <h2 className="mt-2 text-xl font-medium text-gray-600">Page not found</h2>
        <p className="mt-2 text-gray-500">
          Sorry, we couldn't find the page you're looking for.
        </p>
        <div className="mt-6">
          <Link
            to="/dashboard"
            className="btn-primary inline-flex items-center"
          >
            <HomeIcon className="h-4 w-4 mr-2" />
            Go back to dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
