// Ref: https://github.com/marketplace/actions/slither-action#example-workflow-markdown-report

module.exports = async ({ github, context, header, body }) => {
    const collapse_details = '<details> <summary> Click me to view the full report </summary>';
    const close_details = '</details>';

    const comment = [header, collapse_details, body, close_details].join("\n");
  
    const { data: comments } = await github.rest.issues.listComments({
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: context.payload.number,
    });
  
    const botComment = comments.find(
      (comment) =>
        // github-actions bot user
        comment.user.id === 41898282 && comment.body.startsWith(header)
    );
  
    const commentFn = botComment ? "updateComment" : "createComment";
  
    await github.rest.issues[commentFn]({
      owner: context.repo.owner,
      repo: context.repo.repo,
      body: comment,
      ...(botComment
        ? { comment_id: botComment.id }
        : { issue_number: context.payload.number }),
    });
  };