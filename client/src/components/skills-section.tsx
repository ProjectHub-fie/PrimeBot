import { Monitor, Server, Settings, Rocket } from "lucide-react";

interface Skill {
  name: string;
  level: number;
}

interface SkillCategory {
  title: string;
  icon: React.ReactNode;
  color: string;
  skills: Skill[];
}

const skillCategories: SkillCategory[] = [
  {
    title: "Frontend",
    icon: <Monitor className="text-4xl" />,
    color: "text-blue-400",
    skills: [
      { name: "React", level: 5 },
      { name: "TypeScript", level: 4 },
      { name: "Discord.js", level: 4 },
      { name: "Discord.py", level: 3 },
      { name: "Tailwind CSS", level:4 }
    ]
  },
  {
    title: "Backend",
    icon: <Server className="text-4xl" />,
    color: "text-emerald-400",
    skills: [
      { name: "Node.js", level: 5 },
      { name: "mySQL", level: 4 },
      { name: "Python", level: 4 },
      { name: "MongoDB", level: 4 }
    ]
  },
  {
    title: "Tools & DevOps",
    icon: <Settings className="text-4xl" />,
    color: "text-violet-400",
    skills: [
      
      { name: "Git", level: 5 },
      { name: "Vercel", level: 4 },
      { name: "Firebase", level: 5}
    ]
  },
  {
    title: "Specializations",
    icon: <Rocket className="text-4xl" />,
    color: "text-orange-400",
    skills: [
      { name: "Bot Development", level: 4 },
      { name: "Web Development", level: 4 },
      { name: "App Building", level: 3 }
      
    ]
  }
];


const techLogos = [
  { name: "React", icon: "fab fa-react", color: "text-blue-400" },
  { name: "Node.js", icon: "fab fa-node-js", color: "text-emerald-400" },
  { name: "JavaScript", icon: "fab fa-js-square", color: "text-yellow-400" },
  { name: "Python", icon: "fab fa-python", color: "text-violet-400" },
  { name: "GitHub", icon: "fab fa-github", color: "text-slate-300" },
  { name: "discord.js", icon: "fab fa-discord", color: "text-yellow-400" }, // yellow to match JS
  { name: "discord.py", icon: "fab fa-discord", color: "text-blue-400" }   // blue to match Python
];

export default function SkillsSection() {
  const renderSkillDots = (level: number) => {
    return (
      <div className="flex space-x-1">
        {[1, 2, 3, 4, 5].map((dot) => (
          <div
            key={dot}
            className={`w-2 h-2 rounded-full ${
              dot <= level ? "bg-blue-500" : "bg-slate-600"
            }`}
          />
        ))}
      </div>
    );
  };

  return (
    <section id="skills" className="py-20 bg-slate-900">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="text-center mb-16">
          <h2 className="text-4xl md:text-5xl font-bold mb-6">
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-blue-500">
              Skills & Technologies
            </span>
          </h2>
          <p className="text-xl text-slate-300 max-w-2xl mx-auto">
            My technical expertise spans across modern web technologies and development tools
          </p>
        </div>

        {/* Skills Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {skillCategories.map((category, index) => (
            <div
              key={category.title}
              className="bg-slate-800/50 p-8 rounded-2xl border border-slate-700 hover:border-blue-500/50 transition-all duration-300 hover:-translate-y-2"
              data-testid={`skill-category-${index}`}
            >
              <div className={`${category.color} mb-4`}>
                {category.icon}
              </div>
              <h3 className="text-xl font-bold text-white mb-4">{category.title}</h3>
              <div className="space-y-3">
                {category.skills.map((skill) => (
                  <div key={skill.name} className="flex items-center justify-between">
                    <span className="text-slate-300">{skill.name}</span>
                    {renderSkillDots(skill.level)}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Tech Stack Logos */}
        <div className="mt-16 border-t border-slate-700 pt-16">
          <h3 className="text-2xl font-bold text-center text-slate-300 mb-12">
            Technologies I Work With
          </h3>
          <div className="flex flex-wrap justify-center items-center gap-8 opacity-60 hover:opacity-100 transition-opacity duration-500">
            {techLogos.map((tech) => (
              <div
                key={tech.name}
                className={`text-4xl ${tech.color} hover:text-opacity-80 transition-colors duration-200`}
                title={tech.name}
                data-testid={`tech-logo-${tech.name.toLowerCase()}`}
              >
                <i className={tech.icon}></i>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}