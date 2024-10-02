package io.github.mrspock182.iamintegration.service;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class IamService {
    private static final String POLICY_ARN = "arn:aws:iam::103120217022:policy/AccessAPI";

    private final AmazonIdentityManagement iam;

    public IamService(
            @Value("${aws.accessKeyId}") String accessKeyId,
            @Value("${aws.secretAccessKey}") String secretAccessKey,
            @Value("${aws.region}") String region) {
        final BasicAWSCredentials credentials = new BasicAWSCredentials(accessKeyId, secretAccessKey);
        this.iam = AmazonIdentityManagementClientBuilder.standard()
                .withRegion(Regions.fromName(region))
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .build();
    }

    public CreateUserResult createUser(final String userName) {
        final CreateUserRequest request = new CreateUserRequest().withUserName(userName);
        final CreateUserResult createUserResult = iam.createUser(request);
        attachUserPolicy(userName);

        final CreateAccessKeyResult accessKeyResult = createAccessKey(userName);

        // Exibe a chave de acesso para o usuário (AccessKey e SecretAccessKey)
        System.out.println("Access Key ID: " + accessKeyResult.getAccessKey().getAccessKeyId());
        System.out.println("Secret Access Key: " + accessKeyResult.getAccessKey().getSecretAccessKey());

        return createUserResult;
    }

    public void deleteUser(final String userName) {
        deactivateUserAccessKeys(userName);
        deleteUserConsolePassword(userName);
        detachAllUserPolicies(userName);
    }

    private void deactivateUserAccessKeys(final String userName) {
        ListAccessKeysRequest listAccessKeysRequest = new ListAccessKeysRequest().withUserName(userName);
        ListAccessKeysResult listAccessKeysResult = iam.listAccessKeys(listAccessKeysRequest);

        for (AccessKeyMetadata accessKeyMetadata : listAccessKeysResult.getAccessKeyMetadata()) {
            String accessKeyId = accessKeyMetadata.getAccessKeyId();
            UpdateAccessKeyRequest updateAccessKeyRequest = new UpdateAccessKeyRequest()
                    .withUserName(userName)
                    .withAccessKeyId(accessKeyId)
                    .withStatus(StatusType.Inactive);
            iam.updateAccessKey(updateAccessKeyRequest);
        }
    }

    private void detachAllUserPolicies(final String userName) {
        ListAttachedUserPoliciesRequest listAttachedUserPoliciesRequest = new ListAttachedUserPoliciesRequest().withUserName(userName);
        ListAttachedUserPoliciesResult listAttachedUserPoliciesResult = iam.listAttachedUserPolicies(listAttachedUserPoliciesRequest);

        for (AttachedPolicy policy : listAttachedUserPoliciesResult.getAttachedPolicies()) {
            DetachUserPolicyRequest detachUserPolicyRequest = new DetachUserPolicyRequest()
                    .withUserName(userName)
                    .withPolicyArn(policy.getPolicyArn());
            iam.detachUserPolicy(detachUserPolicyRequest);
        }

        ListUserPoliciesRequest listUserPoliciesRequest = new ListUserPoliciesRequest().withUserName(userName);
        ListUserPoliciesResult listUserPoliciesResult = iam.listUserPolicies(listUserPoliciesRequest);

        for (String policyName : listUserPoliciesResult.getPolicyNames()) {
            DeleteUserPolicyRequest deleteUserPolicyRequest = new DeleteUserPolicyRequest()
                    .withUserName(userName)
                    .withPolicyName(policyName);
            iam.deleteUserPolicy(deleteUserPolicyRequest);
        }
    }

    private void deleteUserConsolePassword(final String userName) {
        try {
            DeleteLoginProfileRequest deleteLoginProfileRequest = new DeleteLoginProfileRequest().withUserName(userName);
            iam.deleteLoginProfile(deleteLoginProfileRequest);
        } catch (NoSuchEntityException e) {
            System.out.println("Usuário não tinha senha de console configurada.");
        }
    }

    private CreateAccessKeyResult createAccessKey(String userName) {
        CreateAccessKeyRequest request = new CreateAccessKeyRequest().withUserName(userName);
        return iam.createAccessKey(request);
    }

    private void attachUserPolicy(String userName) {
        AttachUserPolicyRequest attachRequest = new AttachUserPolicyRequest()
                .withUserName(userName)
                .withPolicyArn(POLICY_ARN);
        iam.attachUserPolicy(attachRequest);
    }

}
