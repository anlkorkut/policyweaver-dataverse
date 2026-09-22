using System;
using Microsoft.Xrm.Sdk;

namespace PolicyWeaver.ReadContext
{
    /// <summary>
    /// Pure execution-context probe for the pw_ReadContext Custom API main operation.
    /// This does not decide business-data access or invoke an organization service.
    /// </summary>
    public sealed class ReadContextPlugin : IPlugin
    {
        public const string MessageName = "pw_ReadContext";
        public const string ProtocolVersion = "1";

        public void Execute(IServiceProvider serviceProvider)
        {
            if (serviceProvider == null)
                throw Failure("PWRC_CONTEXT_UNAVAILABLE");

            var context = serviceProvider.GetService(typeof(IPluginExecutionContext))
                as IPluginExecutionContext;
            if (context == null)
                throw Failure("PWRC_CONTEXT_UNAVAILABLE");

            // Microsoft documents stage 30 for a Custom API's main operation.
            // Mode, Depth and InitiatingUserId are deliberately not identity gates.
            if (!string.Equals(context.MessageName, MessageName, StringComparison.Ordinal)
                || context.Stage != 30)
                throw Failure("PWRC_INVALID_REGISTRATION_CONTEXT");

            var input = context.InputParameters;
            var output = context.OutputParameters;
            if (input == null || output == null)
                throw Failure("PWRC_CONTEXT_UNAVAILABLE");

            object rawNonce;
            if (!input.TryGetValue("Nonce", out rawNonce) || !(rawNonce is Guid))
                throw Failure("PWRC_INVALID_NONCE");

            var nonce = (Guid)rawNonce;
            if (nonce == Guid.Empty)
                throw Failure("PWRC_INVALID_NONCE");

            // Only Dataverse-supplied effective context values are returned. Never
            // accept UserId or OrganizationId from request parameters.
            var userId = context.UserId;
            var organizationId = context.OrganizationId;
            if (userId == Guid.Empty || organizationId == Guid.Empty)
                throw Failure("PWRC_INVALID_IDENTITY_CONTEXT");

            // Publish outputs only after every precondition has passed.
            output["UserId"] = userId;
            output["OrganizationId"] = organizationId;
            output["Nonce"] = nonce;
            output["ProtocolVersion"] = ProtocolVersion;
        }

        private static InvalidPluginExecutionException Failure(string safeCode)
        {
            return new InvalidPluginExecutionException(safeCode);
        }
    }
}
