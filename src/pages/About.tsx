import React from 'react';
import './About.css';

const About: React.FC = () => {
  return (
    <div className="about-page">
      <div className="container">
        <header className="about-header">
          <h1>About Me</h1>
          <p>Security Researcher & CTF Enthusiast</p>
        </header>

        <div className="about-content">
          <section className="about-section">
            <h2>Who I Am</h2>
            <p>
              I'm a passionate cybersecurity researcher and CTF enthusiast who loves exploring 
              the depths of security vulnerabilities and exploitation techniques. My journey 
              in the world of ethical hacking began with curiosity and has evolved into a 
              deep passion for understanding how systems can be secured.
            </p>
          </section>

          <section className="about-section">
            <h2>My Expertise</h2>
            <div className="expertise-grid">
              <div className="expertise-item">
                <h3>Web Security</h3>
                <p>IDOR's, XSS, CSRF, and other web vulnerabilities</p>
              </div>
              <div className="expertise-item">
                <h3>Binary Exploitation</h3>
                <p>Binary analysis and software reverse engineering</p>
              </div>
              <div className="expertise-item">
                <h3>Forensics</h3>
                <p>Digital forensics, memory analysis, and incident response</p>
              </div>
            </div>
          </section>

          <section className="about-section">
            <h2>Tools & Technologies</h2>
            <div className="tools-grid">
              <div className="tool-category">
                <h3>Reconnaissance</h3>
                <ul>
                  <li>Nmap</li>
                  <li>Wireshark</li>
                  <li>Recon-ng</li>
                  <li>Shodan</li>
                </ul>
              </div>
              <div className="tool-category">
                <h3>Web Testing</h3>
                <ul>
                  <li>Burp Suite</li>
                  <li>Nuclei</li>
                  <li>SQLMap</li>
                  <li>Nikto</li>
                </ul>
              </div>
              <div className="tool-category">
                <h3>Exploitation</h3>
                <ul>
                  <li>Metasploit</li>
                  <li>Exploit-DB</li>
                  <li>SearchSploit</li>
                  <li>BeEF</li>
                </ul>
              </div>
              <div className="tool-category">
                <h3>Forensics</h3>
                <ul>
                  <li>Autopsy</li>
                  <li>Wireshark</li>
                  <li>Binwalk</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="about-section">
            <h2>Certifications & Achievements</h2>
            <div className="achievements">
              <div className="achievement-item">
                <h3>Certifications</h3>
                <ul>
                  <li>CEH (Certified Ethical Hacker)</li>
                  <li>CISCO Networking Basics</li>
                  <li>Cyber Talents (Cybersecurity Professional)</li>
                  <li>CISCO Introduction To Cybersecurity</li>
                </ul>
              </div>
              <div className="achievement-item">
                <h3>CTF Achievements</h3>
                <ul>
                  <li>Top 10% in multiple CTF competitions</li>
                  <li>Active participant in HackTheBox and TryHackMe</li>
                </ul>
              </div>
            </div>
          </section>

          <section className="about-section">
            <h2>Get In Touch</h2>
            <p>
              I'm always interested in collaborating on security research projects, 
              participating in CTF competitions, or discussing the latest security trends. 
              Feel free to reach out if you'd like to connect!
            </p>
            <div className="contact-info">
              <div className="contact-item">
                <strong>Email:</strong> ctfhuntertux@gmail.com
              </div>
              <div className="contact-item">
                <strong>GitHub:</strong> <a href="https://github.com/Tux-n00b" target="_blank" rel="noopener noreferrer">github.com/Tux-n00b</a>
              </div>
              <div className="contact-item">
                <strong>LinkedIn:</strong> <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer">linkedin.com/in/tux-security</a>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default About; 