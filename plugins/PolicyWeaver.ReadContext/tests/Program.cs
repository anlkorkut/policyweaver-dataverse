using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting.Messaging;
using System.Runtime.Remoting.Proxies;
using System.Threading.Tasks;
using Microsoft.Xrm.Sdk;

namespace PolicyWeaver.ReadContext.Tests
{
    internal static class Program
    {
        private static int Main()
        {
            var tests = new Dictionary<string, Action>
            {
                { "valid_context_exact_outputs", ValidContext },
                { "effective_user_not_initiating_user", EffectiveIdentity },
                { "null_service_provider", () => Reject(null, "PWRC_CONTEXT_UNAVAILABLE") },
                { "missing_context", () => Reject(new Provider(null), "PWRC_CONTEXT_UNAVAILABLE") },
                { "wrong_service_type", () => Reject(new Provider(new object()), "PWRC_CONTEXT_UNAVAILABLE") },
                { "wrong_message", () => RejectChanged("MessageName", "pw_Other", "PWRC_INVALID_REGISTRATION_CONTEXT") },
                { "message_case_is_exact", () => RejectChanged("MessageName", "PW_READCONTEXT", "PWRC_INVALID_REGISTRATION_CONTEXT") },
                { "wrong_stage", () => RejectChanged("Stage", 40, "PWRC_INVALID_REGISTRATION_CONTEXT") },
                { "missing_nonce", () => RejectNonce(null, false) },
                { "string_nonce_rejected", () => RejectNonce(Guid.NewGuid().ToString(), true) },
                { "null_nonce_rejected", () => RejectNonce(null, true) },
                { "empty_nonce_rejected", () => RejectNonce(Guid.Empty, true) },
                { "empty_user_rejected", () => RejectChanged("UserId", Guid.Empty, "PWRC_INVALID_IDENTITY_CONTEXT") },
                { "empty_organization_rejected", () => RejectChanged("OrganizationId", Guid.Empty, "PWRC_INVALID_IDENTITY_CONTEXT") },
                { "null_input_rejected", () => RejectChanged("InputParameters", null, "PWRC_CONTEXT_UNAVAILABLE") },
                { "null_output_rejected", () => RejectChanged("OutputParameters", null, "PWRC_CONTEXT_UNAVAILABLE") },
                { "request_cannot_spoof_identity", SpoofedIdentity },
                { "extra_optional_inputs_ignored", OptionalInputs },
                { "no_unneeded_context_services_or_properties", MinimalContextAccess },
                { "reused_instance_isolates_concurrent_contexts", ConcurrentContexts },
                { "only_expected_external_assembly_references", AssemblyReferences },
                { "no_mutable_instance_state", NoMutableInstanceState }
            };
            int passed = 0;
            foreach (var test in tests)
            {
                try
                {
                    test.Value();
                    passed++;
                    Console.WriteLine("PASS " + test.Key);
                }
                catch (Exception exception)
                {
                    // Never print parameter values, execution identities or exception messages.
                    Console.Error.WriteLine("FAIL " + test.Key + " (" + exception.GetType().Name + ")");
                    return 1;
                }
            }
            Console.WriteLine("Passed " + passed + " local plugin tests. Live Dataverse qualification remains separate.");
            return 0;
        }

        private static void ValidContext()
        {
            var fixture = new Fixture();
            new ReadContextPlugin().Execute(fixture.Provider);
            CheckOutput(fixture);
            Check(fixture.Output.Count == 4);
            Check(fixture.Provider.Requests == 1);
        }

        private static void EffectiveIdentity()
        {
            var fixture = new Fixture();
            fixture.Context.Values["InitiatingUserId"] = Guid.NewGuid();
            Check(!Equals(fixture.Context.Values["InitiatingUserId"], fixture.UserId));
            new ReadContextPlugin().Execute(fixture.Provider);
            CheckOutput(fixture);
            Check(!fixture.Context.Accessed.Contains("InitiatingUserId"));
        }

        private static void SpoofedIdentity()
        {
            var fixture = new Fixture();
            fixture.Input["UserId"] = Guid.NewGuid();
            fixture.Input["OrganizationId"] = Guid.NewGuid();
            fixture.Input["ProtocolVersion"] = "untrusted";
            new ReadContextPlugin().Execute(fixture.Provider);
            CheckOutput(fixture);
        }

        private static void OptionalInputs()
        {
            var fixture = new Fixture();
            fixture.Input["CustomOptionalParameter"] = "ignored";
            fixture.Output["CustomOptionalResponse"] = "preserved";
            new ReadContextPlugin().Execute(fixture.Provider);
            CheckOutput(fixture);
            Check(Equals(fixture.Output["CustomOptionalResponse"], "preserved"));
        }

        private static void MinimalContextAccess()
        {
            var fixture = new Fixture();
            new ReadContextPlugin().Execute(fixture.Provider);
            Check(fixture.Context.Accessed.SetEquals(new[]
            {
                "MessageName", "Stage", "InputParameters", "OutputParameters", "UserId", "OrganizationId"
            }));
            // Provider throws for IOrganizationServiceFactory, ITracingService or any other service.
            Check(fixture.Provider.Requests == 1);
        }

        private static void ConcurrentContexts()
        {
            var plugin = new ReadContextPlugin();
            Parallel.For(0, 200, ignored =>
            {
                var fixture = new Fixture();
                plugin.Execute(fixture.Provider);
                CheckOutput(fixture);
            });
        }

        private static void AssemblyReferences()
        {
            var names = typeof(ReadContextPlugin).Assembly.GetReferencedAssemblies().Select(a => a.Name);
            Check(new HashSet<string>(names).SetEquals(new[] { "mscorlib", "Microsoft.Xrm.Sdk" }));
        }

        private static void NoMutableInstanceState()
        {
            Check(typeof(ReadContextPlugin).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Length == 0);
            Check(typeof(ReadContextPlugin).GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public).All(f => f.IsLiteral));
        }

        private static void RejectChanged(string property, object value, string expectedCode)
        {
            var fixture = new Fixture();
            fixture.Context.Values[property] = value;
            Reject(fixture.Provider, expectedCode);
            Check(fixture.Output.Count == 0);
        }

        private static void RejectNonce(object nonce, bool present)
        {
            var fixture = new Fixture();
            fixture.Input.Clear();
            if (present) fixture.Input["Nonce"] = nonce;
            Reject(fixture.Provider, "PWRC_INVALID_NONCE");
            Check(fixture.Output.Count == 0);
        }

        private static void Reject(IServiceProvider provider, string expectedCode)
        {
            try { new ReadContextPlugin().Execute(provider); }
            catch (InvalidPluginExecutionException exception)
            {
                Check(exception.Message == expectedCode);
                Check(exception.InnerException == null);
                return;
            }
            throw new InvalidOperationException("Expected safe failure.");
        }

        private static void CheckOutput(Fixture fixture)
        {
            Check(Equals(fixture.Output["UserId"], fixture.UserId));
            Check(Equals(fixture.Output["OrganizationId"], fixture.OrganizationId));
            Check(Equals(fixture.Output["Nonce"], fixture.Nonce));
            Check(Equals(fixture.Output["ProtocolVersion"], "1"));
        }

        private static void Check(bool condition)
        {
            if (!condition) throw new InvalidOperationException("Assertion failed.");
        }

        private sealed class Fixture
        {
            public readonly Guid UserId = Guid.NewGuid();
            public readonly Guid OrganizationId = Guid.NewGuid();
            public readonly Guid Nonce = Guid.NewGuid();
            public readonly ParameterCollection Input = new ParameterCollection();
            public readonly ParameterCollection Output = new ParameterCollection();
            public readonly ContextProxy Context;
            public readonly Provider Provider;

            public Fixture()
            {
                Input["Nonce"] = Nonce;
                Context = new ContextProxy(new Dictionary<string, object>
                {
                    { "MessageName", "pw_ReadContext" }, { "Stage", 30 },
                    { "UserId", UserId }, { "OrganizationId", OrganizationId },
                    { "InputParameters", Input }, { "OutputParameters", Output }
                });
                Provider = new Provider(Context.GetTransparentProxy());
            }
        }

        private sealed class Provider : IServiceProvider
        {
            private readonly object context;
            public int Requests { get; private set; }
            public Provider(object context) { this.context = context; }
            public object GetService(Type serviceType)
            {
                Requests++;
                if (serviceType != typeof(IPluginExecutionContext))
                    throw new InvalidOperationException("Unexpected service request.");
                return context;
            }
        }

        private sealed class ContextProxy : RealProxy
        {
            public readonly Dictionary<string, object> Values;
            public readonly HashSet<string> Accessed = new HashSet<string>();
            public ContextProxy(Dictionary<string, object> values) : base(typeof(IPluginExecutionContext))
            {
                Values = values;
            }
            public override IMessage Invoke(IMessage message)
            {
                var call = (IMethodCallMessage)message;
                object value;
                if (call.MethodName.StartsWith("get_", StringComparison.Ordinal)
                    && Values.TryGetValue(call.MethodName.Substring(4), out value))
                {
                    Accessed.Add(call.MethodName.Substring(4));
                    return new ReturnMessage(value, null, 0, call.LogicalCallContext, call);
                }
                return new ReturnMessage(new InvalidOperationException("Unexpected context access."), call);
            }
        }
    }
}
