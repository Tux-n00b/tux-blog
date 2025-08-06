import React, { useEffect, useState } from 'react';
import './BlogCalendar.css';

interface BlogPostMeta {
  date: string; // ISO format
}

const BlogCalendar: React.FC = () => {
  const [activity, setActivity] = useState<Record<string, number>>({});

  useEffect(() => {
    const loadActivity = async () => {
      try {
        const response = await import('../data/blogIndex.json');
        const posts: BlogPostMeta[] = response.default;

        const counts: Record<string, number> = {};

        posts.forEach((post) => {
          const day = post.date.split('T')[0]; // strip time
          counts[day] = (counts[day] || 0) + 1;
        });

        setActivity(counts);
      } catch (err) {
        console.error('Failed to load calendar data:', err);
      }
    };

    loadActivity();
  }, []);

  const getDayClass = (dateStr: string) => {
    const count = activity[dateStr] || 0;
    if (count === 0) return 'calendar-day';
    if (count === 1) return 'calendar-day level-1';
    if (count === 2) return 'calendar-day level-2';
    return 'calendar-day level-3';
  };

  const generateDays = () => {
    const today = new Date();
    const days: React.ReactElement[] = [];
    const yearAgo = new Date();
    yearAgo.setFullYear(today.getFullYear() - 1);

    for (let d = new Date(yearAgo); d <= today; d.setDate(d.getDate() + 1)) {
      const dateStr = d.toISOString().split('T')[0];
      days.push(
        <div
          key={dateStr}
          className={getDayClass(dateStr)}
          title={`${dateStr}: ${activity[dateStr] || 0} posts`}
        ></div>
      );
    }

    return days;
  };

  return (
    <div className="calendar-container">
      <h2>Blog Activity Calendar</h2>
      <div className="calendar-grid">{generateDays()}</div>
    </div>
  );
};

export default BlogCalendar;
