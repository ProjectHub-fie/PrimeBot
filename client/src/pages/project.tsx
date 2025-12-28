import { useRoute } from "wouter";
import ProjectDetail from "@/components/project-detail";

interface Project {
  id: string;
  title: string;
  description: string;
  longDescription: string;
  image: string;
  category: "websites" | "bots" | "utilities";
  tech: string[];
  features: string[];
  highlights: string[];
  liveUrl?: string;
  githubUrl?: string;
  status: string;
  statusColor: string;
  timeline: string;
  teamSize?: string;
  userCount?: string;
}

const projects: Project[] = [
  {
    id: "PrimeBot",
    title: "PrimeBot",
    description: "PrimeBot is a sleek, multipurpose Discord bot built to supercharge your server with essential tools.",
    longDescription: "PrimeBot is a comprehensive Discord bot designed to enhance server functionality with a complete suite of moderation, entertainment, and utility features. Built with performance and reliability in mind, it serves thousands of Discord servers with 99.9% uptime.",
    image: "/primebot.gif",
    category: "bots",
    tech: ["Discord.js", "Node.js", "MySQL", "Docker", "Redis"],
    features: [
      "Dynamic giveaway system with customizable entry requirements",
      "Interactive polls with real-time voting and analytics",
      "Advanced ticket system with category support and logs",
      "Gaming commands including trivia, dice, and mini-games",
      "Comprehensive moderation tools (ban, kick, mute, warn)",
      "Full emoji management suite with bulk upload/delete",
      "Custom command creation and scripting",
      "Role management and auto-role assignment",
      "Welcome/goodbye message system with embeds",
      "Server analytics and activity tracking"
    ],
    highlights: [
      "Serving 500+ Discord servers with 50K+ active users",
      "99.9% uptime with distributed hosting infrastructure",
      "Processed over 1M+ commands successfully",
      "Featured in Discord Bot Lists with 4.8/5 star rating"
    ],
    liveUrl: "https://discord.com/oauth2/authorize?client_id=1352315703830773863&permissions=8&integration_type=0&scope=bot",
    status: "Active",
    statusColor: "bg-green-500",
    timeline: "6 months development",
    teamSize: "Solo project",
    userCount: "50,000+ active users"
  },
  {
    id: "pbo",
    title: "PrimeBot Dashboard",
    description: "Interactive and dynamic website with dashboard for PrimeBot discord bot management.",
    longDescription: "A comprehensive web dashboard for PrimeBot that allows server administrators to configure bot settings, view analytics, manage giveaways, and monitor server activity through an intuitive interface.",
    image: "/primebot.gif",
    category: "websites",
    tech: ["TypeScript", "React", "Node.js", "PostgreSQL", "TailwindCSS"],
    features: [
      "Real-time server analytics and user engagement metrics",
      "Giveaway management with participant tracking",
      "Custom command builder with syntax highlighting",
      "Role and permission management interface",
      "Ticket system administration panel",
      "Bot configuration with live preview",
      "Audit logs and moderation history",
      "Server member insights and activity graphs",
      "Custom embed designer for announcements",
      "API integration for external services"
    ],
    highlights: [
      "Modern React-based dashboard with real-time updates",
      "OAuth integration with Discord for secure authentication",
      "Mobile-responsive design for on-the-go management",
      "Comprehensive admin tools for server management"
    ],
    liveUrl: "https://primebot-online.vercel.app",
    githubUrl: "https://github.com/yourusername/primebot-dashboard",
    status: "Development",
    statusColor: "bg-yellow-500",
    timeline: "3 months development",
    teamSize: "Solo project",
    userCount: "1,000+ dashboard users"
  },
  {
    id: "Sky",
    title: "Sky Task Manager",
    description: "Collaborative task management application with real-time updates and team collaboration features.",
    longDescription: "Sky is a modern task management platform that brings teams together with real-time collaboration, advanced project tracking, and intelligent workflow automation. Designed for productivity and ease of use.",
    image: "/api/placeholder/400/300",
    category: "websites",
    tech: ["React", "Socket.io", "MongoDB", "Express", "JWT", "Redis"],
    features: [
      "Real-time collaborative task editing and updates",
      "Advanced project timeline and milestone tracking",
      "Team chat integration with file sharing",
      "Automated workflow triggers and notifications",
      "Customizable project templates and boards",
      "Time tracking and productivity analytics",
      "Role-based access control and permissions",
      "Integration with popular tools (Slack, GitHub, Jira)",
      "Mobile app with offline sync capabilities",
      "Advanced reporting and team performance metrics"
    ],
    highlights: [
      "Real-time synchronization across all devices",
      "Scalable architecture supporting 10,000+ concurrent users",
      "Advanced analytics with machine learning insights",
      "Enterprise-grade security with end-to-end encryption"
    ],
    liveUrl: "https://yourtasks.com",
    githubUrl: "https://github.com/yourusername/taskmanager",
    status: "Live",
    statusColor: "bg-green-500",
    timeline: "8 months development",
    teamSize: "3 developers",
    userCount: "5,000+ active teams"
  },
  {
    id: "weather-dashboard",
    title: "Weather Dashboard",
    description: "Interactive weather dashboard with location-based forecasts and severe weather alerts.",
    longDescription: "A comprehensive weather application that provides detailed forecasts, historical data analysis, and severe weather monitoring with beautiful data visualizations and location-based services.",
    image: "/api/placeholder/400/300",
    category: "websites",
    tech: ["React", "Chart.js", "OpenWeather API", "Geolocation", "PWA"],
    features: [
      "7-day detailed weather forecasts with hourly breakdowns",
      "Interactive weather maps with radar and satellite imagery",
      "Severe weather alerts and emergency notifications",
      "Historical weather data analysis and trends",
      "Location-based automatic weather updates",
      "Air quality index monitoring and health recommendations",
      "UV index tracking with sun safety alerts",
      "Weather widgets for embedding in other applications",
      "Offline capability with cached forecast data",
      "Multiple location tracking and comparison"
    ],
    highlights: [
      "Progressive Web App with native-like experience",
      "Real-time weather data from multiple reliable sources",
      "Beautiful data visualizations with interactive charts",
      "Accurate severe weather alerting system"
    ],
    liveUrl: "https://yourweather.com",
    githubUrl: "https://github.com/yourusername/weather-dashboard",
    status: "Live",
    statusColor: "bg-green-500",
    timeline: "4 months development",
    teamSize: "Solo project",
    userCount: "2,000+ daily users"
  },
  {
    id: "blog-platform",
    title: "Modern Blog Platform",
    description: "Content management system with markdown support, SEO optimization, and analytics dashboard.",
    longDescription: "A powerful blogging platform that combines the simplicity of markdown writing with advanced SEO tools, comprehensive analytics, and a modern content management system designed for professional bloggers and content creators.",
    image: "/api/placeholder/400/300",
    category: "websites",
    tech: ["React", "Next.js", "Prisma", "PostgreSQL", "MDX", "Stripe"],
    features: [
      "Rich markdown editor with live preview and syntax highlighting",
      "Advanced SEO optimization with meta tag management",
      "Built-in analytics dashboard with reader insights",
      "Comment system with moderation and spam protection",
      "Newsletter integration with subscriber management",
      "Social media auto-posting and cross-platform sharing",
      "Custom theme builder with drag-and-drop interface",
      "Multi-author support with role-based permissions",
      "Scheduled publishing and content calendar",
      "Monetization tools with subscription and paywall support"
    ],
    highlights: [
      "Lightning-fast static site generation with Next.js",
      "SEO-optimized with 95+ PageSpeed Insights score",
      "Integrated payment processing for premium content",
      "Advanced analytics with reader behavior tracking"
    ],
    liveUrl: "https://yourblog.com",
    githubUrl: "https://github.com/yourusername/blog-platform",
    status: "Development",
    statusColor: "bg-yellow-500",
    timeline: "5 months development",
    teamSize: "2 developers",
    userCount: "500+ content creators"
  },
  {
    id: "fitness-tracker",
    title: "Fitness Tracking Website",
    description: "Personal fitness tracking application with workout logging and progress visualization.",
    longDescription: "A comprehensive fitness tracking platform that helps users achieve their health goals through detailed workout logging, nutrition tracking, progress visualization, and social motivation features.",
    image: "/api/placeholder/400/300",
    category: "websites",
    tech: ["React", "D3.js", "Firebase", "PWA", "Service Workers", "TensorFlow.js"],
    features: [
      "Comprehensive workout logging with exercise database",
      "Nutrition tracking with barcode scanning and meal planning",
      "Progress visualization with interactive charts and graphs",
      "Social features for sharing achievements and motivation",
      "AI-powered workout recommendations based on goals",
      "Wearable device integration (Fitbit, Apple Watch, Garmin)",
      "Custom workout plan creation and sharing",
      "Body measurement tracking with photo progress",
      "Challenges and leaderboards for community engagement",
      "Offline workout tracking with sync capabilities"
    ],
    highlights: [
      "AI-powered personal trainer recommendations",
      "Integration with 15+ popular fitness wearables",
      "Progressive Web App with offline workout tracking",
      "Community of 10,000+ fitness enthusiasts"
    ],
    liveUrl: "https://yourfitness.com",
    githubUrl: "https://github.com/yourusername/fitness-tracker",
    status: "Beta",
    statusColor: "bg-blue-500",
    timeline: "7 months development",
    teamSize: "4 developers",
    userCount: "10,000+ fitness enthusiasts"
  }
];

export default function ProjectPage() {
  const [match, params] = useRoute("/project/:id");
  
  if (!match || !params?.id) {
    return <div>Project not found</div>;
  }

  const project = projects.find(p => p.id === params.id);
  
  if (!project) {
    return <div>Project not found</div>;
  }

  return <ProjectDetail project={project} />;
}