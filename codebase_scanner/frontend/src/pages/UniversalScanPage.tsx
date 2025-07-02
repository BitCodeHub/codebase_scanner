import React from 'react';
import { UniversalFileUpload } from '../components/UniversalFileUpload';

const UniversalScanPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-50">
      <UniversalFileUpload />
    </div>
  );
};

export default UniversalScanPage;