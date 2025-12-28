import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage, FormDescription } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { useLocation } from "wouter";
import { apiRequest } from "@/lib/queryClient";
import { LogOut, Plus, Clock, User } from "lucide-react";

const projectRequestSchema = z.object({
  title: z.string().min(1, "Project title is required"),
  description: z.string().min(10, "Please provide at least 10 characters describing your project"),
  budget: z.string().optional(),
  timeline: z.string().optional(),
  technologies: z.array(z.string()).optional(),
});

export default function ProjectRequestPage() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const { user, isLoading, isAuthenticated, logout } = useAuth();
  const queryClient = useQueryClient();

  const form = useForm<z.infer<typeof projectRequestSchema>>({
    resolver: zodResolver(projectRequestSchema),
    defaultValues: {
      title: "",
      description: "",
      budget: "",
      timeline: "",
      technologies: [],
    },
  });

  // Redirect if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      setLocation("/login");
    }
  }, [isAuthenticated, isLoading, setLocation]);

  const { data: userRequests } = useQuery({
    queryKey: ["/api/project-requests"],
    enabled: isAuthenticated,
  });

  const createRequestMutation = useMutation({
    mutationFn: async (data: z.infer<typeof projectRequestSchema>) => {
      return apiRequest("/api/project-requests", "POST", data);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/project-requests"] });
      form.reset();
      toast({
        title: "Request Submitted!",
        description: "Your project request has been submitted successfully. We'll get back to you soon!",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Submission Failed",
        description: error.message || "Failed to submit project request. Please try again.",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (values: z.infer<typeof projectRequestSchema>) => {
    createRequestMutation.mutate(values);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900">
        <div className="text-white text-xl">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect to login
  }

  return (
    <div className="min-h-screen bg-slate-900 py-8 px-4">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Request Your Project</h1>
            <p className="text-slate-400">Tell us about your dream project and we'll bring it to life!</p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-slate-300">
              <User className="h-4 w-4" />
              <span>{user?.firstName} {user?.lastName}</span>
            </div>
            <Button
              variant="outline"
              onClick={() => logout()}
              className="bg-slate-800 border-slate-600 hover:bg-slate-700"
              data-testid="button-logout"
            >
              <LogOut className="h-4 w-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Project Request Form */}
          <Card className="lg:col-span-2 bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Plus className="h-5 w-5" />
                New Project Request
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Form {...form}>
                <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
                  <FormField
                    control={form.control}
                    name="title"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-slate-300">Project Title</FormLabel>
                        <FormControl>
                          <Input
                            {...field}
                            className="bg-slate-700 border-slate-600 text-white"
                            placeholder="e.g., E-commerce website, Mobile app, etc."
                            data-testid="input-project-title"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-slate-300">Project Description</FormLabel>
                        <FormControl>
                          <Textarea
                            {...field}
                            className="bg-slate-700 border-slate-600 text-white min-h-32"
                            placeholder="Describe your project in detail. What features do you need? What problem does it solve?"
                            data-testid="textarea-project-description"
                          />
                        </FormControl>
                        <FormDescription className="text-slate-400">
                          The more details you provide, the better we can understand your needs.
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      control={form.control}
                      name="budget"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-slate-300">Budget Range</FormLabel>
                          <Select onValueChange={field.onChange} value={field.value}>
                            <FormControl>
                              <SelectTrigger className="bg-slate-700 border-slate-600 text-white" data-testid="select-budget">
                                <SelectValue placeholder="Select budget range" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent className="bg-slate-700 border-slate-600">
                              <SelectItem value="under-1k">Under $1,000</SelectItem>
                              <SelectItem value="1k-5k">$1,000 - $5,000</SelectItem>
                              <SelectItem value="5k-10k">$5,000 - $10,000</SelectItem>
                              <SelectItem value="10k-25k">$10,000 - $25,000</SelectItem>
                              <SelectItem value="25k-plus">$25,000+</SelectItem>
                              <SelectItem value="discuss">Let's discuss</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="timeline"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel className="text-slate-300">Timeline</FormLabel>
                          <Select onValueChange={field.onChange} value={field.value}>
                            <FormControl>
                              <SelectTrigger className="bg-slate-700 border-slate-600 text-white" data-testid="select-timeline">
                                <SelectValue placeholder="Select timeline" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent className="bg-slate-700 border-slate-600">
                              <SelectItem value="asap">ASAP</SelectItem>
                              <SelectItem value="1-2-weeks">1-2 weeks</SelectItem>
                              <SelectItem value="1-month">1 month</SelectItem>
                              <SelectItem value="2-3-months">2-3 months</SelectItem>
                              <SelectItem value="3-6-months">3-6 months</SelectItem>
                              <SelectItem value="flexible">Flexible</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>

                  <Button
                    type="submit"
                    className="w-full bg-gradient-to-r from-emerald-500 to-teal-500 text-white hover:from-emerald-600 hover:to-teal-600"
                    disabled={createRequestMutation.isPending}
                    data-testid="button-submit-request"
                  >
                    {createRequestMutation.isPending ? "Submitting..." : "Submit Project Request"}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>

          {/* Previous Requests */}
          <Card className="bg-slate-800 border-slate-700">
            <CardHeader>
              <CardTitle className="text-white flex items-center gap-2">
                <Clock className="h-5 w-5" />
                Your Requests
              </CardTitle>
            </CardHeader>
            <CardContent>
              {userRequests && Array.isArray(userRequests) && userRequests.length > 0 ? (
                <div className="space-y-4">
                  {userRequests.map((request: any) => (
                    <div key={request.id} className="p-4 bg-slate-700 rounded-lg">
                      <h4 className="font-medium text-white mb-2" data-testid={`request-title-${request.id}`}>{request.title}</h4>
                      <p className="text-sm text-slate-400 mb-2 line-clamp-2" data-testid={`request-description-${request.id}`}>
                        {request.description}
                      </p>
                      <div className="flex items-center justify-between">
                        <Badge
                          variant={request.status === 'pending' ? 'secondary' : 'default'}
                          className="text-xs"
                          data-testid={`request-status-${request.id}`}
                        >
                          {request.status}
                        </Badge>
                        <span className="text-xs text-slate-500">
                          {new Date(request.createdAt).toLocaleDateString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-slate-400 py-8">
                  <Plus className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>No project requests yet.</p>
                  <p className="text-sm">Submit your first request!</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}