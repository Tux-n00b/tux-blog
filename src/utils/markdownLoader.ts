// This utility helps with loading markdown files
// The system now reads markdown files using fetch from the public directory

export const loadMarkdownContent = async (filename: string): Promise<string> => {
  try {
    // Use fetch to load markdown files from the public/posts directory
    const response = await fetch(`${process.env.PUBLIC_URL}/posts/${filename}`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const content = await response.text();
    return content;
  } catch (error) {
    console.error(`Error loading markdown file ${filename}:`, error);
    throw new Error(`Failed to load markdown content: ${filename}`);
  }
};

// Legacy function for backward compatibility
export const getMarkdownContent = async (filename: string): Promise<string> => {
  return loadMarkdownContent(filename);
};