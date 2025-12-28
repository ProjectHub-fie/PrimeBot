import { Button } from "@/components/ui/button";
import { Download } from "lucide-react";

export default function AboutSection() {
  const stats = [
    { value: "50+", label: "Projects Completed", color: "text-blue-400" },
    { value: "5+", label: "Years Experience", color: "text-emerald-400" },
    { value: "25+", label: "Happy Clients", color: "text-violet-400" },
    { value: "15+", label: "Technologies", color: "text-orange-400" }
  ];

  return (
    <section id="about" className="py-20 bg-slate-800/50">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="max-w-4xl mx-auto">
          
          {/* About Content */}
          <div>
            <h2 className="text-4xl md:text-5xl font-bold mb-8">
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-violet-500">
                About us.
              </span>
            </h2>
            
            <div className="space-y-6 text-slate-300 leading-relaxed">
              <p className="text-lg">
                Hello all, welcome to ProjectHub. ProjectHub is where developers go to turn ideas 
                into real, working code. Designed for programmers with some experience under their
                belt, ProjectHub bridges the gap between basic tutorials and advanced, enterprise-level
                platforms. Here, you’ll find:
              </p>
              
              <p>
               • <strong>Collaborative projects </strong>that sharpen your skills and expand your portfolio.</p>
            <p>• <strong>Practical resources </strong>focused on building, not just learning theory.</p>
           <p> • <strong>A supportive community</strong> of coders who speak your language — no hand-holding, no gatekeeping.
              </p>
              
              <p>
                We’re always looking for fresh ideas and exciting builds. <strong>Got a project worth sharing?
                Bring it to ProjectHub and build it with us.</strong>
              </p>
            </div>

            {/* Stats */}
            <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-6">
              {stats.map((stat, index) => (
                <div key={index} className="text-center" data-testid={`stat-${index}`}>
                  <div className={`text-3xl font-bold ${stat.color} mb-2`}>
                    {stat.value}
                  </div>
                  <div className="text-slate-400 text-sm">{stat.label}</div>
                </div>
              ))}
            </div>

            {/* Download Resume Button 
            <div className="mt-12">
              <Button
                className="bg-gradient-to-r from-blue-500 to-violet-500 text-white px-8 py-4 rounded-xl font-medium hover:shadow-lg hover:shadow-blue-500/25 transition-all duration-300 hover:-translate-y-1"
                data-testid="button-download-resume"
               >
                <Download className="w-4 h-4 mr-3" />
                Download Resume
              </Button>
            </div> */}
          </div>

        </div>
      </div>
    </section>
  );
}
