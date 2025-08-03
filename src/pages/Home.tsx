import React from 'react';
import { Link } from 'react-router-dom';
import './Home.css';

const Home: React.FC = () => {
  return (
    <div className="home">
      <section className="hero">
        <div className="container">
          <div className="hero-content">
            <h1 className="hero-title">
              <span className="terminal-prompt">$</span> TUX_BLOG
              <span className="terminal-cursor"></span>
            </h1>
            <p className="hero-subtitle">
              CTF Writeups • Security Research • Technical Blogs
            </p>
            <p className="hero-description">
              Welcome to my digital space where I share my journey through cybersecurity challenges, 
              CTF writeups, and technical discoveries. From web exploitation to binary exploitation, 
              join me as I explore the fascinating world of security research.
            </p>
            <div className="hero-actions">
              <Link to="/blog" className="btn btn-primary">
                EXPLORE WRITEUPS
              </Link>
              <Link to="/about" className="btn btn-secondary">
                ABOUT ME
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section className="features">
        <div className="container">
          <h2>What You'll Find Here</h2>
          <div className="features-grid">
            <div className="feature-card">
              <h3>CTF Writeups</h3>
              <p>Detailed walkthroughs of Capture The Flag challenges, from beginner to advanced levels.</p>
            </div>
            <div className="feature-card">
              <h3>Vulnhub Writeups</h3>
              <p>Insights into vulnerabilities, exploitation techniques, and walkthoughs of Vulnhub machines.</p>
            </div>
            <div className="feature-card">
              <h3>Technical Guides</h3>
              <p>Step-by-step tutorials on tools, techniques, and methodologies in cybersecurity.</p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home; 