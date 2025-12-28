import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { ExternalLink, Github, Download, Bot, ArrowLeft, Calendar, Users, Star, CheckCircle2 } from "lucide-react";
import { useLocation } from "wouter";

interface ProjectDetailProps {
  project: {
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
  };
}

export default function ProjectDetail({ project }: ProjectDetailProps) {
  const [, setLocation] = useLocation();

  const getActionIcon = (category: string) => {
    switch (category) {
      case "websites":
        return <ExternalLink className="w-4 h-4 mr-2" />;
      case "bots":
        return <Bot className="w-4 h-4 mr-2" />;
      case "utilities":
        return <Download className="w-4 h-4 mr-2" />;
      default:
        return <ExternalLink className="w-4 h-4 mr-2" />;
    }
  };

  const getActionText = (category: string) => {
    switch (category) {
      case "websites":
        return "Visit Website";
      case "bots":
        return "Add to Discord";
      case "utilities":
        return "Download";
      default:
        return "View Project";
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 py-8">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Back Button */}
        <Button
          variant="ghost"
          onClick={() => setLocation("/")}
          className="mb-8 text-slate-400 hover:text-white"
          data-testid="button-back-to-projects"
        >
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Projects
        </Button>

        {/* Project Header */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4">
            <h1 className="text-4xl md:text-5xl font-bold text-white">
              {project.title}
            </h1>
            <div className={`${project.statusColor} text-white px-4 py-2 rounded-full text-sm font-medium`}>
              {project.status}
            </div>
          </div>
          <p className="text-xl text-slate-300 leading-relaxed">
            {project.longDescription}
          </p>
        </div>

        {/* Project Image */}
        <div className="relative mb-8 rounded-2xl overflow-hidden">
          <img 
            src={project.image}
            alt={project.title}
            className="w-full h-64 md:h-96 object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-slate-900/60 to-transparent"></div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-4 mb-8">
          {project.liveUrl && (
            <Button
              className="bg-blue-500 hover:bg-blue-600 text-white px-6 py-3 rounded-lg font-medium"
              onClick={() => window.open(project.liveUrl, '_blank')}
              data-testid="button-live-demo"
            >
              {getActionIcon(project.category)}
              {getActionText(project.category)}
            </Button>
          )}
          {project.githubUrl && (
            <Button
              variant="outline"
              className="border-slate-600 hover:border-blue-500 hover:text-blue-400 text-slate-300 px-6 py-3 rounded-lg font-medium"
              onClick={() => window.open(project.githubUrl, '_blank')}
              data-testid="button-view-code"
            >
              <Github className="w-4 h-4 mr-2" />
              View Code
            </Button>
          )}
        </div>

        <div className="grid md:grid-cols-2 gap-8">
          {/* Project Details */}
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <h3 className="text-xl font-bold text-white mb-4">Project Details</h3>
              
              <div className="space-y-4">
                <div className="flex items-center gap-3">
                  <Calendar className="w-5 h-5 text-blue-400" />
                  <div>
                    <p className="text-slate-400 text-sm">Timeline</p>
                    <p className="text-white">{project.timeline}</p>
                  </div>
                </div>
                
                {project.teamSize && (
                  <div className="flex items-center gap-3">
                    <Users className="w-5 h-5 text-blue-400" />
                    <div>
                      <p className="text-slate-400 text-sm">Team Size</p>
                      <p className="text-white">{project.teamSize}</p>
                    </div>
                  </div>
                )}
                
                {project.userCount && (
                  <div className="flex items-center gap-3">
                    <Star className="w-5 h-5 text-blue-400" />
                    <div>
                      <p className="text-slate-400 text-sm">Users</p>
                      <p className="text-white">{project.userCount}</p>
                    </div>
                  </div>
                )}
              </div>

              <Separator className="my-6 bg-slate-600" />

              {/* Tech Stack */}
              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Technology Stack</h4>
                <div className="flex flex-wrap gap-2">
                  {project.tech.map((tech) => (
                    <Badge
                      key={tech}
                      className="bg-blue-500/20 text-blue-400 border-blue-500/30 px-3 py-1 rounded-full"
                    >
                      {tech}
                    </Badge>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Features */}
          <Card className="bg-slate-800 border-slate-700">
            <CardContent className="p-6">
              <h3 className="text-xl font-bold text-white mb-4">Key Features</h3>
              <div className="space-y-3">
                {project.features.map((feature, index) => (
                  <div key={index} className="flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-green-400 mt-0.5 flex-shrink-0" />
                    <p className="text-slate-300">{feature}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Project Highlights */}
        {project.highlights.length > 0 && (
          <Card className="bg-slate-800 border-slate-700 mt-8">
            <CardContent className="p-6">
              <h3 className="text-xl font-bold text-white mb-4">Project Highlights</h3>
              <div className="grid md:grid-cols-2 gap-4">
                {project.highlights.map((highlight, index) => (
                  <div key={index} className="flex items-start gap-3">
                    <Star className="w-5 h-5 text-yellow-400 mt-0.5 flex-shrink-0" />
                    <p className="text-slate-300">{highlight}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}