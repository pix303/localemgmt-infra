package main

import (
	"github.com/pulumi/pulumi-aws/sdk/v5/go/aws/s3"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		err := createBucket(ctx)
		if err != nil {
			return err
		}
		return nil
	})
}

func createApiGateway() {

}

func createBucket(ctx *pulumi.Context) error {
	bucket, err := s3.NewBucket(ctx, "locale-bucket", nil)
	if err != nil {
		return err
	}

	ctx.Export("bucketName", bucket.ID())
	return nil
}
