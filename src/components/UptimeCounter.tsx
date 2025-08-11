import React, { useEffect, useState } from 'react';
import './UptimeCounter.css';

const UptimeCounter: React.FC = () => {
  const launchDate = new Date('2025-08-01T00:00:00Z');

  const [time, setTime] = useState({
    days: '00',
    hours: '00',
    minutes: '00',
    seconds: '00'
  });

  useEffect(() => {
    const update = () => {
      const now = new Date();
      const diff = now.getTime() - launchDate.getTime();

      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
      const minutes = Math.floor((diff / (1000 * 60)) % 60);
      const seconds = Math.floor((diff / 1000) % 60);

      setTime({
        days: String(days).padStart(2, '0'),
        hours: String(hours).padStart(2, '0'),
        minutes: String(minutes).padStart(2, '0'),
        seconds: String(seconds).padStart(2, '0')
      });
    };

    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="uptime-digital">
      <div className="uptime-display">
        <span>{time.days} <small>days</small></span> :
        <span>{time.hours} <small>hours</small></span> :
        <span>{time.minutes} <small>minutes</small></span> :
        <span>{time.seconds} <small>seconds</small></span>
      </div>
    </div>
  );
};

export default UptimeCounter;
