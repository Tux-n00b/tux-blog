import React from 'react';
import BlogCalendar from '../components/BlogCalendar';
import './Progress.css';

const Progress: React.FC = () => {
  return (
    <div className="progress-page container">
      <h1>📈 My Progress</h1>

      <section className="calendar-section">
        <h2>🗓 Blog Posting Calendar</h2>
        <BlogCalendar />
      </section>
      <section className="github-stats">
        <h2>📊 GitHub Stats</h2>
        <div className="stats-grid">
          <img
            src="https://github-readme-stats.vercel.app/api?username=Tux-n00b&theme=dark&hide_border=true&include_all_commits=false&count_private=true"
            alt="GitHub Stats"
          />
          <img
            src="https://nirzak-streak-stats.vercel.app/?user=Tux-n00b&theme=dark&hide_border=true"
            alt="GitHub Streak"
          />
          <img
            src="https://github-readme-stats.vercel.app/api/top-langs/?username=Tux-n00b&theme=dark&hide_border=true&include_all_commits=false&count_private=true&layout=compact"
            alt="Top Languages"
          />
        </div>
      </section>
    </div>
  );
};

export default Progress;
