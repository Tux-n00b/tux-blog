// src/pages/Progress.tsx
import React from 'react';
import './Progress.css';

const Progress: React.FC = () => {
  return (
    <div className="progress-page">
      <div className="container">
        <header className="progress-header">
          <h1>📈 My Progress</h1>
          <p>Tracking personal growth, contributions, and skills</p>
        </header>

        {/* GitHub Stats */}
        <section className="progress-section">
          <h2>📊 GitHub Stats</h2>
          <div className="stats-grid">
            <img
              src="https://github-readme-stats.vercel.app/api?username=Tux-n00b&theme=shadow_green&hide_border=false&include_all_commits=true&count_private=true"
              alt="GitHub Stats"
            />
            <img
              src="https://nirzak-streak-stats.vercel.app/?user=Tux-n00b&theme=shadow_green&hide_border=false"
              alt="GitHub Streak"
            />
            <img
              src="https://github-readme-stats.vercel.app/api/top-langs/?username=Tux-n00b&theme=shadow_green&hide_border=false&layout=compact"
              alt="Top Languages"
            />
          </div>
        </section>
      </div>
    </div>
  );
};

export default Progress;
