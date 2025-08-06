import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import './Navbar.css';

const Navbar: React.FC = () => {
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="container">
        <Link to="/" className="navbar-brand">
          <span className="brand-text">&gt;_Tux.</span>
          <span className="terminal-cursor"></span>
        </Link>
        
        <ul className="nav-links">
          <li>
            <Link 
              to="/" 
              className={location.pathname === '/' ? 'active' : ''}
            >
              HOME
            </Link>
          </li>
          <li>
            <Link 
              to="/blog" 
              className={location.pathname === '/blog' ? 'active' : ''}
            >
              BLOG
            </Link>
          </li>
          <li>
            <Link 
              to="/about" 
              className={location.pathname === '/about' ? 'active' : ''}
            >
              ABOUT
            </Link>
          </li>
          <li>
            <Link 
              to="/progress"
              className={location.pathname === '/progress' ? 'active' : ''}
            >
              PROGRESS
            </Link>
          </li>
        </ul>
      </div>
    </nav>
  );
};

export default Navbar; 