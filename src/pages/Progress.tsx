// src/pages/Progress.tsx
import React, { useEffect, useState } from 'react';
import './Progress.css';
import UptimeCounter from '../components/UptimeCounter';

const Progress: React.FC = () => {
  const startDate = new Date('2025-08-01T00:00:00Z'); // Site start date (UTC)
  const [uptime, setUptime] = useState<string>('0 days 0 hrs 0 mins 0 secs');

  useEffect(() => {
    const updateUptime = () => {
      const now = new Date();
      const diff = now.getTime() - startDate.getTime();

      const days = Math.floor(diff / (1000 * 60 * 60 * 24));
      const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
      const minutes = Math.floor((diff / (1000 * 60)) % 60);
      const seconds = Math.floor((diff / 1000) % 60);

      setUptime(`${days} days ${hours} hrs ${minutes} mins ${seconds} secs`);
    };

    updateUptime();
    const timer = setInterval(updateUptime, 1000);

    return () => clearInterval(timer);
  }, []);

  return (
    <div className="progress-page container">
      <header className="progress-header">
        <h1 className="progress-title">TuxPulse 🐧</h1>
        <p className="progress-subtitle">
          Tracking my blogging streaks and coding journey
        </p>
      </header>

      {/* Site Uptime Section */}
        <section className="uptime-section">
          <UptimeCounter />
        </section>

      {/* GitHub Stats Section */}
      <section className="progress-section">
        <h2 className="section-title">📊 GitHub Stats</h2>
        <div className="stats-grid">
          <div className="card">
            <img
              src="https://github-readme-stats.vercel.app/api?username=Tux-n00b&theme=shadow_green&hide_border=false&include_all_commits=true&count_private=true"
              alt="GitHub Stats"
            />
          </div>
          <div className="card">
            <img
              src="https://nirzak-streak-stats.vercel.app/?user=Tux-n00b&theme=shadow_green&hide_border=false"
              alt="GitHub Streak"
            />
          </div>
          <div className="card">
            <img
              src="https://github-readme-stats.vercel.app/api/top-langs/?username=Tux-n00b&theme=shadow_green&hide_border=false&layout=compact"
              alt="Top Languages"
            />
          </div>
        </div>
      </section>
    </div>
  );
};

export default Progress;
