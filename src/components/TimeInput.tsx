import React from 'react';
import { Clock } from 'lucide-react';

type TimeInputProps = {
  value: string;
  onChange: (time: string) => void;
  label?: string;
  placeholder?: string;
  required?: boolean;
  disabled?: boolean;
  className?: string;
};

const TimeInput: React.FC<TimeInputProps> = ({
  value,
  onChange,
  label = 'Horário',
  placeholder = 'HH:mm',
  required = false,
  disabled = false,
  className = '',
}) => {

  const handleTimeChange = (newTime: string) => {
    onChange(newTime);
  };


  return (
    <div>
      {label && (
        <label className="block text-sm font-medium text-gray-700">
          {label} {required && <span className="text-red-500">*</span>}
        </label>
      )}
      
      <div className="relative">
        <input
          type="time"
          value={value}
          onChange={(e) => handleTimeChange(e.target.value)}
          placeholder={placeholder}
          required={required}
          disabled={disabled}
          className={`input pr-10 ${className}`}
          step="60" // 1 minute steps
        />
        
        <div className="absolute right-3 top-1/2 transform -translate-y-1/2">
          <Clock className="h-4 w-4 text-gray-400" />
        </div>
      </div>
    </div>
  );
};

export default TimeInput;