import React, { useState, useEffect } from 'react';
import PostCard from '../components/PostCard';
import { BlogPost } from '../types/blog';
import './Blog.css';

const Blog: React.FC = () => {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTag, setSelectedTag] = useState<string>('all');
  const [tags, setTags] = useState<string[]>([]);

  useEffect(() => {
    const loadPosts = async () => {
      try {
        // In a real app, you'd fetch this from an API
        // For now, we'll import the JSON directly
        const response = await fetch(`${process.env.PUBLIC_URL}/data/blogIndex.json`);
        const postsData: BlogPost[] = await response.json();

        
        setPosts(postsData);
        
        // Extract unique tags
        const allTags = postsData.flatMap(post => post.tags);
        const uniqueTags = Array.from(new Set(allTags));
        setTags(uniqueTags);
        
        setLoading(false);
      } catch (error) {
        console.error('Error loading posts:', error);
        setLoading(false);
      }
    };

    loadPosts();
  }, []);

  const filteredPosts = selectedTag === 'all' 
    ? posts 
    : posts.filter(post => post.tags.includes(selectedTag));

  if (loading) {
    return (
      <div className="blog-page">
        <div className="container">
          <div className="loading">
            <div className="loading-spinner"></div>
            <p>Loading posts...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="blog-page">
      <div className="container">
        <header className="blog-header">
          <h1>Blog Posts</h1>
          <p>CTF writeups, security research, and technical guides</p>
        </header>

        <div className="blog-filters">
          <button 
            className={`filter-btn ${selectedTag === 'all' ? 'active' : ''}`}
            onClick={() => setSelectedTag('all')}
          >
            ALL ({posts.length})
          </button>
          {tags.map(tag => (
            <button
              key={tag}
              className={`filter-btn ${selectedTag === tag ? 'active' : ''}`}
              onClick={() => setSelectedTag(tag)}
            >
              {tag.toUpperCase()} ({posts.filter(post => post.tags.includes(tag)).length})
            </button>
          ))}
        </div>

        <div className="posts-grid">
          {filteredPosts.length > 0 ? (
            filteredPosts.map(post => (
              <PostCard key={post.slug} post={post} />
            ))
          ) : (
            <div className="no-posts">
              <p>No posts found for the selected tag.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Blog; 