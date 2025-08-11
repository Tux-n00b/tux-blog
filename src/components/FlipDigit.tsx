import React, { useEffect, useState } from 'react';
import './FlipDigit.css';

interface FlipDigitProps {
  value: string; // Always 2-digit string (e.g., "07")
}

const FlipDigit: React.FC<FlipDigitProps> = ({ value }) => {
  const [prevValue, setPrevValue] = useState(value);
  const [flipping, setFlipping] = useState(false);

  useEffect(() => {
    if (value !== prevValue) {
      setFlipping(true);
      const timeout = setTimeout(() => {
        setFlipping(false);
        setPrevValue(value);
      }, 600); // match animation duration
      return () => clearTimeout(timeout);
    }
  }, [value, prevValue]);

  return (
    <div className="flip-digit">
      <div className={`flip-inner ${flipping ? 'flipping' : ''}`}>
        <div className="flip-front">{prevValue}</div>
        <div className="flip-back">{value}</div>
      </div>
    </div>
  );
};

export default FlipDigit;
